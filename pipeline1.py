import requests
import pandas as pd
import json
import time
import random
from datetime import datetime, timezone
from requests.auth import HTTPBasicAuth

from pathlib import Path
import joblib
# from ml_model import predict_df


# ==========================================================
# CONFIGURATION
# ==========================================================

INDEXER_IP = "192.168.56.104"
INDEXER_PORT = 9200
USERNAME = "admin"
PASSWORD = "adminAdmin1*"

BASE_URL = f"https://{INDEXER_IP}:{INDEXER_PORT}"
HEADERS = {"Content-Type": "application/json"}

CUSTOM_INDEX = "wazuh-ml-data-0001"
SOURCE_INDEX = "wazuh-archives-4.x-*"
# SIM_ARCHIVES_INDEX = "wazuh-archives-4.x-sim"

# CSV_FILE = "wazuh_alerts_20251229_000057.csv"

# CSV_FILE = "last_wazuh.csv"

# updated 
# OUTPUT_PATH = "exports/index_dump_test.csv"

CSV_CHUNK_SIZE = 1000

LOCAL_LOG_FILE = r"C:\Users\Lenovo\Documents\ml_predictions.log"
POLL_INTERVAL = 10

requests.packages.urllib3.disable_warnings()
auth = HTTPBasicAuth(USERNAME, PASSWORD)

def check_indexer():
    print(" Checking Indexer connectivity...")
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
        requests.delete(
            f"{BASE_URL}/_search/scroll",
            auth=auth,
            headers=HEADERS,
            json={"scroll_id": [scroll_id]},
            verify=False,
        )
    return pd.DataFrame(docs)

def ingest_csv_and_dump(CSV_FILE: str, index_name: str, output_path: str) -> str:
    """Inputs: CSV_FILE path, target index name, output CSV path.
    Output: path to saved CSV containing all docs read back from index."""
    check_indexer()

    # Delete/recreate index (keeps your mapping logic)
    requests.delete(f"{BASE_URL}/{index_name}", auth=auth, headers=HEADERS, verify=False)
    mapping = {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "event_type": {"type": "keyword"},
                "ml_label": {"type": "keyword"},
                "risk_score": {"type": "float"},
                "ml_model": {"type": "keyword"},
                "agent": {"properties": {"id": {"type": "keyword"}, "name": {"type": "keyword"}}},
            }
        },
    }
    requests.put(f"{BASE_URL}/{index_name}", auth=auth, headers=HEADERS, json=mapping, verify=False).raise_for_status()

    # Ingest CSV in chunks
    total_rows = 0
    for chunk in pd.read_csv(CSV_FILE, chunksize=CSV_CHUNK_SIZE):
        bulk_index_dataframe(chunk, index_name)
        total_rows += len(chunk)
        time.sleep(0.1)

    # Refresh and read back
    requests.post(f"{BASE_URL}/{index_name}/_refresh", auth=auth, headers=HEADERS, verify=False)
    df_all = scroll_all(index_name)

    # Save locally
    out_path = Path(output_path) # or Path(OUTPUT_PATH)?????????? NO it is inputted in automate.py
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df_all.to_csv(out_path, index=False)
    print(f" Indexed {total_rows} rows and exported {len(df_all)} rows to {out_path}")
    return str(out_path)



##########################Partie 2 ####################################

from pathlib import Path
import json
import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, StandardScaler, LabelEncoder
from sklearn.impute import SimpleImputer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, f1_score

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

def train_and_save_best_model(dataset_path: str, output_model_path: str, output_metrics_path: str = "models/severity_metrics.json"):
    df = pd.read_csv(dataset_path, low_memory=False)

    # Normalize severity
    sev = df.get("severity", pd.Series([None] * len(df))).astype(str).str.lower().str.strip()
    sev = sev.map({"low": "low", "medium": "medium", "med": "medium", "high": "high", "critical": "critical", "crit": "critical"})
    valid = {"low", "medium", "high", "critical"}
    df = df.loc[sev.isin(valid)].copy()
    df["severity"] = sev[sev.isin(valid)]

    # Label encode target
    label_encoder = LabelEncoder()
    df["severity_encoded"] = label_encoder.fit_transform(df["severity"])
    class_labels = list(label_encoder.classes_)

    # Time features
    if "@timestamp" in df.columns:
        ts = pd.to_datetime(df["@timestamp"], errors="coerce")
        df["hour"] = ts.dt.hour
        df["dayofweek"] = ts.dt.dayofweek
        df["month"] = ts.dt.month
    else:
        df["hour"] = df["dayofweek"] = df["month"] = np.nan

    # Feature selection
    text_candidates = ["rule.description", "data.win.eventdata.commandLine", "raw", "rule.mitre.id"]
    cat_candidates = ["agent.name", "location", "agent.id", "rule.id"]
    num_candidates = ["hour", "dayofweek", "month"]
    existing = set(df.columns)
    text_cols = [c for c in text_candidates if c in existing]
    cat_cols = [c for c in cat_candidates if c in existing]
    num_cols = [c for c in num_candidates if c in existing]

    # Clean text
    for c in text_cols:
        df[c] = clean_text_series(df[c])

    # Mask level leaks in raw
    if "raw" in df.columns:
        patterns = [
            r'"level"\s*:\s*\d+',
            r"'level'\s*:\s*\d+",
            r'"severity"\s*:\s*"[a-zA-Z]+"',
            r"'severity'\s*:\s*'[a-zA-Z]+'",
            r'"rule"\s*:\s*\{[^}]*"level"\s*:\s*\d+[^}]*\}',
            r"'rule'\s*:\s*\{[^}]*'level'\s*:\s*\d+[^}]*\}",
        ]
        raw_series = df["raw"].astype(str)
        for pat in patterns:
            raw_series = raw_series.str.replace(pat, "<MASK>", regex=True)
        df["raw"] = raw_series

    # Drop high-cardinality cat cols
    max_card = 50
    cat_cols = [c for c in cat_cols if df[c].nunique(dropna=True) <= max_card]

    feature_cols = text_cols + cat_cols + num_cols
    if not feature_cols:
        raise ValueError("No usable feature columns found.")

    X = df[feature_cols].copy()
    y = df["severity_encoded"].copy()

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=SEED, stratify=y
    )
    cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=SEED)

    # Pipelines
    text_imputer = SimpleImputer(strategy="constant", fill_value="")
    cat_imputer = SimpleImputer(strategy="most_frequent")
    num_imputer = SimpleImputer(strategy="median")

    text_pipeline = Pipeline([
        ("imputer", text_imputer),
        ("to_text", FunctionTransformer(combine_text, validate=False)),
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=5000)),
    ])
    cat_pipeline = Pipeline([
        ("imputer", cat_imputer),
        ("onehot", OneHotEncoder(handle_unknown="ignore")),
    ])
    num_pipeline = Pipeline([
        ("imputer", num_imputer),
        ("scaler", StandardScaler(with_mean=False)),
    ])

    transformers = []
    if text_cols: transformers.append(("text", text_pipeline, text_cols))
    if cat_cols:  transformers.append(("cat", cat_pipeline, cat_cols))
    if num_cols:  transformers.append(("num", num_pipeline, num_cols))

    preprocess = ColumnTransformer(transformers)

    logreg = Pipeline([
        ("preprocess", preprocess),
        ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", solver="liblinear")),
    ])

    # Fit
    logreg.fit(X_train, y_train)

    # Evaluate
    y_pred = logreg.predict(X_test)
    f1_macro = f1_score(y_test, y_pred, average="macro")
    print("F1_macro (LogReg tuned-ish):", f1_macro)
    print(classification_report(y_test, y_pred, target_names=class_labels))

    # Save model payload with extras
    payload = {
        "model": logreg,
        "feature_cols": feature_cols,
        "class_labels": class_labels,
        "label_encoder": label_encoder,
    }
    out_path = Path(output_model_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(payload, out_path)

    metrics = {"f1_macro": f1_macro, "class_labels": class_labels}
    Path(output_metrics_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_metrics_path).write_text(json.dumps(metrics, indent=2))

    print("Saved model:", out_path)
    print("Saved metrics:", output_metrics_path)
    return str(out_path), metrics

