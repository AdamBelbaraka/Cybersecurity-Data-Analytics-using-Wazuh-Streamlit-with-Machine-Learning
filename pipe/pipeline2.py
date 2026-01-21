
import requests
import pandas as pd
import json
import time
import random
from datetime import datetime, timezone
from requests.auth import HTTPBasicAuth
from pathlib import Path
import joblib
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold, RandomizedSearchCV
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, StandardScaler, LabelEncoder
from sklearn.impute import SimpleImputer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.decomposition import TruncatedSVD
from sklearn.metrics import classification_report, f1_score, accuracy_score, balanced_accuracy_score
from sklearn.utils.class_weight import compute_class_weight
try:
    import xgboost as xgb
except Exception:
    xgb = None

# ==========================================================
# CONFIGURATION
# ==========================================================

INDEXER_IP = "192.168.56.104"
INDEXER_PORT = 9200
USERNAME = "admin"
PASSWORD = "Ensam2025?"
# ?????????????????? password 

BASE_URL = f"https://{INDEXER_IP}:{INDEXER_PORT}"
HEADERS = {"Content-Type": "application/json"}

# CUSTOM_INDEX = "wazuh-ml-data-0001"
SOURCE_INDEX = "wazuh-archives-4.x-*"
SIM_ARCHIVES_INDEX = "wazuh-archives-4.x-sim"

CSV_CHUNK_SIZE = 1000
LOCAL_LOG_FILE = r"C:\Users\Lenovo\Documents\ml_predictions.log"
POLL_INTERVAL = 10

requests.packages.urllib3.disable_warnings()
auth = HTTPBasicAuth(USERNAME, PASSWORD)

def check_indexer():
    print("Checking Indexer connectivity.")
    resp = requests.get(BASE_URL, auth=auth, headers=HEADERS, verify=False)
    resp.raise_for_status()
    print("Indexer reachable")

def bulk_index_dataframe(df: pd.DataFrame, index_name: str) -> None:
    lines = []
    for _, row in df.iterrows():
        lines.append(json.dumps({"index": {"_index": index_name}}))
        lines.append(json.dumps(row.dropna().to_dict()))
    payload = "\n".join(lines) + "\n"
    resp = requests.post(
        f"{BASE_URL}/_bulk",
        auth=auth,
        headers={"Content-Type": "application/x-ndjson"},
        data=payload.encode("utf-8"),
        verify=False,
    )
    resp.raise_for_status()
    if resp.json().get("errors"):
        raise RuntimeError("Bulk ingest reported errors")

def scroll_all(index: str, size: int = 1000, scroll: str = "2m") -> pd.DataFrame:
    """Read ALL documents from an Elasticsearch index, regardless of size, and return them as a Pandas DataFrame."""
    docs = []
    query = {"size": size, "query": {"match_all": {}}}
    resp = requests.post(
        f"{BASE_URL}/{index}/_search?scroll={scroll}",
        auth=auth,
        headers=HEADERS,
        json=query,
        verify=False,
    )
    resp.raise_for_status()
    data = resp.json()
    scroll_id = data.get("_scroll_id")
    hits = data.get("hits", {}).get("hits", [])

    while hits:
        # Continue fetching pages until Elasticsearch returns no more documents
        docs.extend([h["_source"] for h in hits])
        resp = requests.post(
            f"{BASE_URL}/_search/scroll",
            auth=auth,
            headers=HEADERS,
            json={"scroll": scroll, "scroll_id": scroll_id},
            verify=False,
        )
        resp.raise_for_status()
        data = resp.json()
        hits = data.get("hits", {}).get("hits", [])
        scroll_id = data.get("_scroll_id")

    if scroll_id:
        # Cleanup scroll context
        requests.delete(
            f"{BASE_URL}/_search/scroll",
            auth=auth,
            headers=HEADERS,
            json={"scroll_id": [scroll_id]},
            verify=False,
        )
    return pd.DataFrame(docs)


########################## Partie 2 ####################################

SEED = 42
np.random.seed(SEED)

def clean_text_series(series: pd.Series) -> pd.Series:
    cleaned = series.fillna("").astype(str).str.lower()
    cleaned = cleaned.str.replace(r"[\x00-\x1f]+", " ", regex=True)
    cleaned = cleaned.str.replace(r"\s+", " ", regex=True).str.strip()
    return cleaned

def combine_text(x):
    if hasattr(x, "fillna"):
        return x.fillna("").astype(str).agg(" ".join, axis=1)
    return pd.DataFrame(x).fillna("").astype(str).agg(" ".join, axis=1)

def to_dense_matrix(x):
    return x.toarray() if hasattr(x, "toarray") else x



############################### Predictions ################################################

import sys, types

# --- Shim for unpickling pipelines that reference combine_text ---
shim_mod = sys.modules.setdefault(__name__, types.SimpleNamespace())
shim_mod.combine_text = combine_text

# --- Load model payload and prepare prediction ---
# def load_model_payload(model_path: str):
#     payload = joblib.load(model_path)  # expects {"model", "feature_cols", .}
#     if "model" not in payload or "feature_cols" not in payload:
#         raise ValueError("Model payload missing required keys")
#     return payload



# --- Load model and metadata ---
def load_model_and_metadata(model_path: str, metrics_path: str = None):
    """
    Load the trained model from pipeline1/model.ipynb.
    The model is a full sklearn Pipeline with preprocessing included.
    Optionally load metrics to get class labels.
    """
    # model = joblib.load(model_path)
    # !!!!! to update 

    model = joblib.load("models/best_severity_model.joblib/best_severity_model.joblib")
    
    class_labels = None
    if metrics_path:
        try:
            metrics_data = json.load(open(metrics_path, "r"))
            # Extract class_labels from metrics
            if "class_labels" in metrics_data:
                class_labels = metrics_data["class_labels"]
            elif "results" in metrics_data and len(metrics_data["results"]) > 0:
                class_labels = metrics_data["results"][0].get("class_labels")
        except Exception as e:
            print(f"Warning: Could not load metrics from {metrics_path}: {e}")
    
    return {"model": model, "class_labels": class_labels}


def predict_event(model_data: dict, event_src: dict) -> dict:
    """
    Predict severity for a single event using the trained model.
    The model includes all preprocessing (text cleaning, feature engineering, etc.)
    so we pass the raw event directly.
    
    Args:
        model_data: dict with "model" (sklearn Pipeline) and "class_labels" (list)
        event_src: dict with raw event data
    
    Returns:
        dict with prediction results
    """
    model = model_data["model"]
    class_labels = model_data.get("class_labels", [])
    
    # Create DataFrame with single event
    df = pd.DataFrame([event_src])
    
    # Model expects specific feature columns - let's get them from model's expected input
    # The model's preprocessor will handle missing columns
    try:
        # Get numeric prediction
        pred_encoded = model.predict(df)[0]
        
        # Convert encoded prediction back to label string if class_labels available
        if class_labels and isinstance(pred_encoded, (int, np.integer)):
            severity_label = class_labels[int(pred_encoded)] if int(pred_encoded) < len(class_labels) else str(pred_encoded)
        else:
            severity_label = str(pred_encoded)
    except Exception as e:
        print(f"Warning: Prediction failed - {e}. Returning 'unknown'")
        severity_label = "unknown"
    
    # Format output prediction
    return {
        "@timestamp": event_src.get("@timestamp") or datetime.now(timezone.utc).isoformat(),
        "event_type": "ml_prediction",
        "severity": severity_label,
        "ml_model": "best_severity_model",
        "agent": {
            "id": event_src.get("agent", {}).get("id"),
            "name": event_src.get("agent", {}).get("name"),
        },
    }

def _json_default(o):
    import numpy as np
    if isinstance(o, np.generic):
        return o.item()
    raise TypeError(f"Object of type {o.__class__.__name__} is not JSON serializable")


def write_prediction(log_path: str, pred: dict) -> None:
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)
    #  mode d ecriture append
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(pred, default=_json_default) + "\n")



def poll_new_events(
    base_url: str,
    auth,
    headers: dict,
    source_index: str,
    last_ts: str = None,
    size: int = 100,
    search_after=None
):
    query = {
        "size": size,
        "sort": [
            {"@timestamp": "asc"},
            {"_id": "asc"}
        ],
        "query": {"match_all": {}}
    }

    if last_ts and not search_after:
        query["query"] = {"range": {"@timestamp": {"gt": last_ts}}}

    if search_after:
        query["search_after"] = search_after

    resp = requests.post(
        f"{base_url}/{source_index}/_search",
        auth=auth,
        headers=headers,
        json=query,
        verify=False,
    )
    resp.raise_for_status()
    return resp.json()["hits"]["hits"]



def run_prediction_cycle(
    model_path: str,
    base_url: str,
    username: str,
    password: str,
    source_index: str,
    log_path: str,
    last_ts: str,
    size: int = 5,
    search_after=None,
    metrics_path="models/best_severity_model.joblib/severity_metrics.json"

):
    # to update path names !!
    auth = HTTPBasicAuth(username, password)
    headers = {"Content-Type": "application/json"}
    # payload = load_model_payload(model_path)

    payload = load_model_and_metadata(model_path,metrics_path)

    # simulate send data to ml index 




    #  poll  starts from lasts_ts , time nefore we ran the run pred cycle function

    hits = poll_new_events(base_url, auth, headers, source_index, last_ts, size=size, search_after=search_after)

       # testing 

    print("hits:", len(hits))

    preds = []
    new_search_after = None

    # what if hits is null ??? safe in loop 
    if not hits:
        return [], search_after
    

    numberPreds = 0

    for hit in hits:
        src = hit.get("_source", {})
        # event en input a la prediction 
        pred = predict_event(payload, src)
        write_prediction(log_path, pred)
        numberPreds += 1
        preds.append(pred)

        new_search_after = hit.get("sort")  # checkpoint eg: "sort": ["2025-01-21T10:05:00Z", "X7K29..."]
    
    print(f"Processed {numberPreds} new events for prediction.")

    return preds, new_search_after , numberPreds