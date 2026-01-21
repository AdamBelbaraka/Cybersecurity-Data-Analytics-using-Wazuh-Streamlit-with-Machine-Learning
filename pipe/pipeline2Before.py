
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

# ################################## #

# def train_and_save_best_model(dataset_path: str, output_model_path: str, output_metrics_path: str = "models/severity_metrics.json"):
#     df = pd.read_csv(dataset_path, low_memory=False)

#     sev = df.get("severity", pd.Series([None] * len(df))).astype(str).str.lower().str.strip()
#     sev = sev.map({"low": "low", "medium": "medium", "med": "medium", "high": "high", "critical": "critical", "crit": "critical"})
#     valid = {"low", "medium", "high", "critical"}
#     df = df.loc[sev.isin(valid)].copy()
#     df["severity"] = sev[sev.isin(valid)]              

#     label_encoder = LabelEncoder()
#     df["severity_encoded"] = label_encoder.fit_transform(df["severity"])
#     class_labels = list(label_encoder.classes_)

#     if "@timestamp" in df.columns:
#         ts = pd.to_datetime(df["@timestamp"], errors="coerce")
#         df["hour"] = ts.dt.hour
#         df["dayofweek"] = ts.dt.dayofweek
#         df["month"] = ts.dt.month
#     else:
#         df["hour"] = df["dayofweek"] = df["month"] = np.nan

#     text_candidates = ["rule.description", "data.win.eventdata.commandLine", "raw", "rule.mitre.id"]
#     cat_candidates = ["agent.name", "location", "agent.id", "rule.id"]
#     num_candidates = ["hour", "dayofweek", "month"]
#     existing = set(df.columns)
#     text_cols = [c for c in text_candidates if c in existing]
#     cat_cols = [c for c in cat_candidates if c in existing]
#     num_cols = [c for c in num_candidates if c in existing]

#     for c in text_cols:
#         df[c] = clean_text_series(df[c])

#     if "raw" in df.columns:
#         patterns = [
#             r'"level"\s*:\s*\d+',
#             r"'level'\s*:\s*\d+",
#             r'"severity"\s*:\s*"[a-zA-Z]+"',
#             r"'severity'\s*:\s*'[a-zA-Z]+'",
#             r'"rule"\s*:\s*\{[^}]*"level"\s*:\s*\d+[^}]*\}',
#             r"'rule'\s*:\s*\{[^}]*'level'\s*:\s*\d+[^}]*\}'",
#         ]
#         raw_series = df["raw"].astype(str)
#         for pat in patterns:
#             raw_series = raw_series.str.replace(pat, "<MASK>", regex=True)
#         df["raw"] = raw_series

#     max_card = 50
#     cat_cols = [c for c in cat_cols if df[c].nunique(dropna=True) <= max_card]

#     feature_cols = text_cols + cat_cols + num_cols
#     if not feature_cols:
#         raise ValueError("No usable feature columns found.")

#     X = df[feature_cols].copy()
#     y = df["severity_encoded"].copy()

#     X_train, X_test, y_train, y_test = train_test_split(
#         X, y, test_size=0.2, random_state=SEED, stratify=y
#     )

#     text_imputer = SimpleImputer(strategy="constant", fill_value="")
#     cat_imputer = SimpleImputer(strategy="most_frequent")
#     num_imputer = SimpleImputer(strategy="median")

#     text_pipeline = Pipeline([
#         ("imputer", text_imputer),
#         ("to_text", FunctionTransformer(combine_text, validate=False)),
#         ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=5000)),
#     ])
#     cat_pipeline = Pipeline([
#         ("imputer", cat_imputer),
#         ("onehot", OneHotEncoder(handle_unknown="ignore")),
#     ])
#     num_pipeline_scaled = Pipeline([
#         ("imputer", num_imputer),
#         ("scaler", StandardScaler(with_mean=False)),
#     ])
#     num_pipeline_plain = Pipeline([
#         ("imputer", num_imputer),
#     ])

#     transformers_scaled = []
#     transformers_plain = []
#     if text_cols:
#         transformers_scaled.append(("text", text_pipeline, text_cols))
#         transformers_plain.append(("text", text_pipeline, text_cols))
#     if cat_cols:
#         transformers_scaled.append(("cat", cat_pipeline, cat_cols))
#         transformers_plain.append(("cat", cat_pipeline, cat_cols))
#     if num_cols:
#         transformers_scaled.append(("num", num_pipeline_scaled, num_cols))
#         transformers_plain.append(("num", num_pipeline_plain, num_cols))

#     preprocess_scaled = ColumnTransformer(transformers_scaled)
#     preprocess_plain = ColumnTransformer(transformers_plain)

#     def evaluate_model(model, X_eval, y_eval, label):
#         preds = model.predict(X_eval)
#         metrics = {
#             "model": label,
#             "accuracy": float(accuracy_score(y_eval, preds)),
#             "balanced_accuracy": float(balanced_accuracy_score(y_eval, preds)),
#             "f1_macro": float(f1_score(y_eval, preds, average="macro")),
#             "f1_weighted": float(f1_score(y_eval, preds, average="weighted")),
#             "classification_report": classification_report(y_eval, preds, target_names=class_labels),
#         }
#         return metrics

#     cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=SEED)

#     # Logistic Regression
#     logreg = Pipeline([
#         ("preprocess", preprocess_scaled),
#         ("clf", LogisticRegression(
#             max_iter=1000,
#             class_weight="balanced",
#             penalty="l2",
#             solver="liblinear",
#         )),
#     ])
#     logreg_param = {"clf__C": [0.01, 0.05, 0.1]}
#     logreg_search = RandomizedSearchCV(
#         logreg,
#         logreg_param,
#         n_iter=5,
#         scoring="f1_macro",
#         cv=cv,
#         n_jobs=-1,
#         random_state=SEED,
#         verbose=1,
#     )
#     logreg_search.fit(X_train, y_train)

#     # Random Forest
#     rf = Pipeline([
#         ("preprocess", preprocess_plain),
#         ("to_dense", FunctionTransformer(to_dense_matrix, validate=False)),
#         ("clf", RandomForestClassifier(
#             n_estimators=50,
#             max_depth=6,
#             min_samples_leaf=10,
#             min_samples_split=20,
#             max_features=0.3,
#             bootstrap=True,
#             class_weight="balanced_subsample",
#             random_state=SEED,
#         )),
#     ])
#     rf_param = {"clf__max_depth": [4, 6, 8], "clf__min_samples_leaf": [5, 10]}
#     rf_search = RandomizedSearchCV(
#         rf,
#         rf_param,
#         n_iter=4,
#         scoring="f1_macro",
#         cv=cv,
#         n_jobs=-1,
#         random_state=SEED,
#         verbose=1,
#     )
#     rf_search.fit(X_train, y_train)

#     # XGBoost
#     xgb_search = None
#     if xgb is not None:
#         classes = np.unique(y_train)
#         class_weights = compute_class_weight(class_weight="balanced", classes=classes, y=y_train)
#         weight_map = {cls: w for cls, w in zip(classes, class_weights)}
#         sample_weight = y_train.map(weight_map).values

#         xgb_model = xgb.XGBClassifier(
#             objective="multi:softprob",
#             num_class=len(class_labels),
#             random_state=SEED,
#             n_estimators=50,
#             max_depth=3,
#             learning_rate=0.2,
#             subsample=0.6,
#             colsample_bytree=0.5,
#             reg_lambda=20,
#             reg_alpha=10,
#             gamma=5,
#             tree_method="hist",
#             eval_metric="mlogloss",
#             n_jobs=-1,
#         )
#         xgb_pipe = Pipeline([
#             ("preprocess", preprocess_plain),
#             ("svd", TruncatedSVD(n_components=200, random_state=SEED)),
#             ("to_dense", FunctionTransformer(to_dense_matrix, validate=False)),
#             ("clf", xgb_model),
#         ])
#         xgb_param = {"clf__max_depth": [2, 3], "clf__subsample": [0.6], "clf__learning_rate": [0.1, 0.2]}
#         xgb_search = RandomizedSearchCV(
#             xgb_pipe,
#             xgb_param,
#             n_iter=2,
#             scoring="f1_macro",
#             cv=cv,
#             n_jobs=-1,
#             random_state=SEED,
#             verbose=1,
#         )
#         xgb_search.fit(X_train, y_train, clf__sample_weight=sample_weight)

#     results = []
#     results.append(evaluate_model(logreg_search.best_estimator_, X_test, y_test, "LogReg tuned"))
#     results.append(evaluate_model(rf_search.best_estimator_, X_test, y_test, "RandomForest tuned"))
#     if xgb_search is not None:
#         results.append(evaluate_model(xgb_search.best_estimator_, X_test, y_test, "XGBoost tuned"))

#     results_df = pd.DataFrame(results).sort_values("f1_macro", ascending=False)
#     best_label = results_df.iloc[0]["model"]

#     if best_label == "LogReg tuned":
#         best_model = logreg_search.best_estimator_
#         best_params = logreg_search.best_params_
#     elif best_label == "RandomForest tuned":
#         best_model = rf_search.best_estimator_
#         best_params = rf_search.best_params_
#     else:
#         best_model = xgb_search.best_estimator_
#         best_params = xgb_search.best_params_ if xgb_search is not None else {}

#     payload = {
#         "model": best_model,
#         "feature_cols": feature_cols,
#         "class_labels": class_labels,
#         "label_encoder": label_encoder,
#     }
#     out_path = Path(output_model_path)
#     out_path.parent.mkdir(parents=True, exist_ok=True)
#     joblib.dump(payload, out_path)

#     metrics = {
#         "best_model": best_label,
#         "best_params": best_params,
#         "models": results,
#         "class_labels": class_labels,
#     }
#     Path(output_metrics_path).parent.mkdir(parents=True, exist_ok=True)
#     Path(output_metrics_path).write_text(json.dumps(metrics, indent=2))

#     print("Saved model:", out_path)
#     print("Saved metrics:", output_metrics_path)
#     return str(out_path), metrics


############################### Predictions ################################################

import sys, types

# --- Shim for unpickling pipelines that reference combine_text ---
shim_mod = sys.modules.setdefault(__name__, types.SimpleNamespace())
shim_mod.combine_text = combine_text

# --- Load model payload and prepare prediction ---
def load_model_payload(model_path: str):
    payload = joblib.load(model_path)  # expects {"model", "feature_cols", .}
    if "model" not in payload or "feature_cols" not in payload:
        raise ValueError("Model payload missing required keys")
    return payload


#  FIXED: timestamp from event (not now)
def predict_event(model_payload, event_src: dict) -> dict:
    model = model_payload["model"]
    feature_cols = model_payload["feature_cols"]
    df = pd.DataFrame([event_src])

    for col in feature_cols:
        if col not in df.columns:
            df[col] = np.nan

    X = df[feature_cols].copy()
    labels =model.predict(X)

  
    #  format of outputted prediction
    return {
        "@timestamp": event_src.get("@timestamp") or datetime.now(timezone.utc).isoformat(),
        "event_type": "ml_prediction",
        "severity": str(labels[0]),
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
):
    auth = HTTPBasicAuth(username, password)
    headers = {"Content-Type": "application/json"}
    payload = load_model_payload(model_path)


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