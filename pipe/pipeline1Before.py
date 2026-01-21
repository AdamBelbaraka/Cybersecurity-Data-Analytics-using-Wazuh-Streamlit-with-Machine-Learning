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

# CUSTOM_INDEX = "wazuh-ml-data-0001"

CUSTOM_INDEX = "ml-data-0001"

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

    # ------------------------------
    # 1.Check if index exists
    # ------------------------------
    resp = requests.head(
        f"{BASE_URL}/{index_name}",
        auth=auth,
        headers=HEADERS,
        verify=False
    )


    if resp.status_code == 200:
        # ------------------------------
        # 2️. Delete the index if it exists
        # ------------------------------
        print(f"Index '{index_name}' exists. ")

        print(f"Index '{index_name}' exists. Deleting...")


        # Delete/recreate index (keeps your mapping logic)
        requests.delete(f"{BASE_URL}/{index_name}", auth=auth, headers=HEADERS, verify=False).raise_for_status()
        print("Deleted successfully.")

    elif resp.status_code == 404:
        print(f"Index '{index_name}' does not exist. Will create it.")
    else:
        raise Exception(f"Unexpected response checking index: {resp.status_code} {resp.text}")

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
    #  create index 
    requests.put(f"{BASE_URL}/{index_name}", auth=auth, headers=HEADERS, json=mapping, verify=False).raise_for_status()

    print(f"Index '{index_name}' created successfully.")


    

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


# def ingest_csv_and_dump(CSV_FILE: str, index_name: str, output_path: str) -> str:
#     """Inputs: CSV_FILE path, target index name, output CSV path.
#     Output: path to saved CSV containing all docs read back from index."""
#     check_indexer()

#     # Delete/recreate index (keeps your mapping logic)
#     requests.delete(f"{BASE_URL}/{index_name}", auth=auth, headers=HEADERS, verify=False)
#     mapping = {
#         "settings": {"number_of_shards": 1, "number_of_replicas": 0},
#         "mappings": {
#             "properties": {
#                 "@timestamp": {"type": "date"},
#                 "event_type": {"type": "keyword"},
#                 "ml_label": {"type": "keyword"},
#                 "risk_score": {"type": "float"},
#                 "ml_model": {"type": "keyword"},
#                 "agent": {"properties": {"id": {"type": "keyword"}, "name": {"type": "keyword"}}},
#             }
#         },
#     }
#     requests.put(f"{BASE_URL}/{index_name}", auth=auth, headers=HEADERS, json=mapping, verify=False).raise_for_status()

    


    

#     # Ingest CSV in chunks
#     total_rows = 0
#     for chunk in pd.read_csv(CSV_FILE, chunksize=CSV_CHUNK_SIZE):
#         bulk_index_dataframe(chunk, index_name)
#         total_rows += len(chunk)
#         time.sleep(0.1)

#     # Refresh and read back
#     requests.post(f"{BASE_URL}/{index_name}/_refresh", auth=auth, headers=HEADERS, verify=False)
#     df_all = scroll_all(index_name)

#     # Save locally
#     out_path = Path(output_path) # or Path(OUTPUT_PATH)?????????? NO it is inputted in automate.py
#     out_path.parent.mkdir(parents=True, exist_ok=True)
#     df_all.to_csv(out_path, index=False)
#     print(f" Indexed {total_rows} rows and exported {len(df_all)} rows to {out_path}")
#     return str(out_path)



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




def train_and_save_best_model(data_path="./wazuh_logs.csv", models_dir="./models"):
    """
    Complete training pipeline: preprocessing, processing, and training of models.
    Saves the best model based on F1 macro score.
    Exact logic from model.ipynb without visualizations.
    
    Parameters:
    -----------
    data_path : str
        Path to the wazuh_logs.csv file
    models_dir : str
        Directory to save the best model and metrics
    
    Returns:
    --------
    dict : Dictionary containing results with best model info
    """
    
    # ============ DATA LOADING ============
    DATA_PATH = Path(data_path)
    if not DATA_PATH.exists():
        raise FileNotFoundError(f"Missing dataset: {DATA_PATH}")
    
    df = pd.read_csv(DATA_PATH, low_memory=False)
    print("Shape:", df.shape)
    
    # ============ LABEL CLEANING & NORMALIZATION ============
    raw_severity = df.get("severity", pd.Series([None] * len(df)))
    sev = raw_severity.astype(str).str.lower().str.strip()
    
    mapping = {
        "low": "low",
        "medium": "medium",
        "med": "medium",
        "high": "high",
        "critical": "critical",
        "crit": "critical",
    }
    
    sev = sev.map(mapping)
    
    valid = {"low", "medium", "high", "critical"}
    mask_valid = sev.isin(valid)
    
    if (~mask_valid).any():
        bad_count = int((~mask_valid).sum())
        print(f"Dropping {bad_count} rows with invalid severity.")
    
    df = df.loc[mask_valid].copy()
    df["severity"] = sev[mask_valid]
    
    print("Severity distribution:\n", df["severity"].value_counts())
    
    # Encode label
    label_encoder = LabelEncoder()
    df["severity_encoded"] = label_encoder.fit_transform(df["severity"])
    class_labels = list(label_encoder.classes_)
    print("Label mapping:", dict(zip(class_labels, range(len(class_labels)))))
    
    # ============ IMPUTERS PREPARATION ============
    text_imputer = SimpleImputer(strategy="constant", fill_value="")
    cat_imputer = SimpleImputer(strategy="most_frequent")
    num_imputer = SimpleImputer(strategy="median")
    
    # ============ TIMESTAMP FEATURE ENGINEERING ============
    if "@timestamp" in df.columns:
        ts = pd.to_datetime(df["@timestamp"], errors="coerce")
        df["hour"] = ts.dt.hour
        df["dayofweek"] = ts.dt.dayofweek
        df["month"] = ts.dt.month
        df["_ts"] = ts
        df = df.drop(columns=["@timestamp"])
        print("Timestamp features added: hour, dayofweek, month")
    else:
        df["hour"] = np.nan
        df["dayofweek"] = np.nan
        df["month"] = np.nan
        print("@timestamp not found, using NaN for time features")
    
    # ============ FEATURE SELECTION & TEXT CLEANING ============
    # Text candidates
    text_candidates = [
        "rule.description",
        "data.win.eventdata.commandLine",
        "raw",
        "rule.mitre.id",
    ]
    
    # Categorical candidates
    cat_candidates = ["agent.name", "location", "agent.id", "rule.id"]
    
    # Numerical candidates
    num_candidates = ["hour", "dayofweek", "month"]
    
    existing_cols = set(df.columns)
    text_cols = [c for c in text_candidates if c in existing_cols]
    cat_cols = [c for c in cat_candidates if c in existing_cols]
    num_cols = [c for c in num_candidates if c in existing_cols]
    
    # Clean text
    for c in text_cols:
        df[c] = clean_text_series(df[c])
    
    # Mask level info in raw to avoid data leakage
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
    
    # Deduplication
    subset = [c for c in ["rule.id", "raw", "rule.description"] if c in df.columns]
    if subset:
        before = len(df)
        df = df.drop_duplicates(subset=subset).reset_index(drop=True)
        removed = before - len(df)
        print(f"Duplicates removed: {removed}")
    
    # Drop categorical cols with high cardinality
    max_card = 50
    kept_cat = []
    dropped_cat = []
    for c in cat_cols:
        n_unique = df[c].nunique(dropna=True)
        if n_unique <= max_card:
            kept_cat.append(c)
        else:
            dropped_cat.append(c)
    
    cat_cols = kept_cat
    
    print("Text cols:", text_cols)
    print("Cat cols (kept):", cat_cols)
    print("Cat cols (dropped):", dropped_cat)
    print("Num cols:", num_cols)
    
    # Define features and target
    feature_cols = text_cols + cat_cols + num_cols
    X = df[feature_cols].copy()
    y = df["severity_encoded"].copy()
    
    print("Final feature columns:", feature_cols)
    print("Class labels:", class_labels)
    
    # ============ TRAIN/TEST SPLIT ============
    if "_ts" in df.columns and df["_ts"].notna().any():
        df_sorted = df.sort_values("_ts").reset_index(drop=True)
        split_idx = int(len(df_sorted) * 0.8)
        train_df = df_sorted.iloc[:split_idx]
        test_df = df_sorted.iloc[split_idx:]
        
        X_train = train_df[feature_cols]
        y_train = train_df["severity_encoded"]
        X_test = test_df[feature_cols]
        y_test = test_df["severity_encoded"]
        
        cv = TimeSeriesSplit(n_splits=3)
        cv_splits = list(cv.split(X_train))
        print("Using temporal split + TimeSeriesSplit")
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=0.2,
            random_state=SEED,
            stratify=y,
        )
        
        if "rule.id" in df.columns:
            groups_train = df.loc[X_train.index, "rule.id"]
            cv = GroupKFold(n_splits=3)
            cv_splits = list(cv.split(X_train, y_train, groups=groups_train))
            print("Using stratified split + GroupKFold(rule.id)")
        else:
            cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=SEED)
            cv_splits = cv
            print("Using stratified split + StratifiedKFold")
    
    print("Train size:", X_train.shape, "Test size:", X_test.shape)
    
    # ============ PREPROCESSING SETUP ============
    text_pipeline = Pipeline([
        ("imputer", text_imputer),
        ("to_text", FunctionTransformer(combine_text, validate=False)),
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=5000)),
    ])
    
    cat_pipeline = Pipeline([
        ("imputer", cat_imputer),
        ("onehot", OneHotEncoder(handle_unknown="ignore")),
    ])
    
    num_pipeline_scaled = Pipeline([
        ("imputer", num_imputer),
        ("scaler", StandardScaler(with_mean=False)),
    ])
    
    num_pipeline_plain = Pipeline([
        ("imputer", num_imputer),
    ])
    
    transformers_scaled = []
    transformers_plain = []
    
    if text_cols:
        transformers_scaled.append(("text", text_pipeline, text_cols))
        transformers_plain.append(("text", text_pipeline, text_cols))
    if cat_cols:
        transformers_scaled.append(("cat", cat_pipeline, cat_cols))
        transformers_plain.append(("cat", cat_pipeline, cat_cols))
    if num_cols:
        transformers_scaled.append(("num", num_pipeline_scaled, num_cols))
        transformers_plain.append(("num", num_pipeline_plain, num_cols))
    
    preprocess_scaled = ColumnTransformer(transformers_scaled)
    preprocess_plain = ColumnTransformer(transformers_plain)
    
    if not transformers_scaled:
        raise ValueError("No usable feature columns found. Check text/cat/num columns.")
    
    # ============ MODEL TRAINING ============
    
    # 1. Logistic Regression Baseline
    print("\n=== Training Logistic Regression Baseline ===")
    logreg_base = Pipeline([
        ("preprocess", preprocess_scaled),
        ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", solver="liblinear")),
    ])
    
    logreg_base.fit(X_train, y_train)
    print("Baseline Logistic Regression trained.")
    
    # 2. Logistic Regression with tuning
    print("\n=== Training Logistic Regression with Tuning ===")
    logreg = Pipeline([
        ("preprocess", preprocess_scaled),
        ("clf", LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            penalty="l2",
            solver="liblinear",
        )),
    ])
    
    logreg_param = {
        "clf__C": [0.01, 0.05, 0.1],
    }
    
    logreg_search = RandomizedSearchCV(
        logreg,
        logreg_param,
        n_iter=5,
        scoring="f1_macro",
        cv=cv_splits,
        n_jobs=-1,
        random_state=SEED,
        verbose=1,
    )
    
    logreg_search.fit(X_train, y_train)
    print("Best LogisticRegression params:", logreg_search.best_params_)
    
    best_logreg = logreg_search.best_estimator_
    y_pred = best_logreg.predict(X_test)
    print("Logistic Regression Evaluation on Test Set:")
    print(classification_report(y_test, y_pred, target_names=class_labels))
    
    # 3. Random Forest
    print("\n=== Training Random Forest with Tuning ===")
    rf = Pipeline([
        ("preprocess", preprocess_plain),
        ("to_dense", FunctionTransformer(to_dense_matrix, validate=False)),
        ("clf", RandomForestClassifier(
            n_estimators=50,
            max_depth=6,
            min_samples_leaf=10,
            min_samples_split=20,
            max_features=0.3,
            bootstrap=True,
            class_weight="balanced_subsample",
            random_state=SEED,
        )),
    ])
    
    rf_param = {
        "clf__max_depth": [4, 6, 8],
        "clf__min_samples_leaf": [5, 10],
    }
    
    rf_search = RandomizedSearchCV(
        rf,
        rf_param,
        n_iter=4,
        scoring="f1_macro",
        cv=cv_splits,
        n_jobs=-1,
        random_state=SEED,
        verbose=1,
    )
    
    rf_search.fit(X_train, y_train)
    print("Best RandomForest params:", rf_search.best_params_)
    
    best_rf = rf_search.best_estimator_
    y_pred = best_rf.predict(X_test)
    print("Random Forest Evaluation on Test Set:")
    print(classification_report(y_test, y_pred, target_names=class_labels))
    
    # 4. XGBoost
    xgb_search = None
    if xgb is None:
        print("\n=== XGBoost is not installed. Skipping XGBoost training. ===")
    else:
        print("\n=== Training XGBoost with Tuning ===")
        classes = np.unique(y_train)
        class_weights = compute_class_weight(class_weight="balanced", classes=classes, y=y_train)
        weight_map = {cls: w for cls, w in zip(classes, class_weights)}
        sample_weight = y_train.map(weight_map).values
        
        xgb_model = xgb.XGBClassifier(
            objective="multi:softprob",
            num_class=len(class_labels),
            random_state=SEED,
            n_estimators=50,
            max_depth=3,
            learning_rate=0.2,
            subsample=0.6,
            colsample_bytree=0.5,
            reg_lambda=20,
            reg_alpha=10,
            gamma=5,
            tree_method="hist",
            eval_metric="mlogloss",
            n_jobs=-1,
        )
        
        xgb_pipe = Pipeline([
            ("preprocess", preprocess_plain),
            ("svd", TruncatedSVD(n_components=200, random_state=SEED)),
            ("to_dense", FunctionTransformer(to_dense_matrix, validate=False)),
            ("clf", xgb_model),
        ])
        
        xgb_param = {
            "clf__max_depth": [2, 3],
            "clf__subsample": [0.6],
            "clf__learning_rate": [0.1, 0.2],
        }
        
        xgb_search = RandomizedSearchCV(
            xgb_pipe,
            xgb_param,
            n_iter=2,
            scoring="f1_macro",
            cv=cv_splits,
            n_jobs=-1,
            random_state=SEED,
            verbose=1,
        )
        
        xgb_search.fit(X_train, y_train, clf__sample_weight=sample_weight)
        print("Best XGBoost params:", xgb_search.best_params_)
        
        best_xgb = xgb_search.best_estimator_
        y_pred = best_xgb.predict(X_test)
        print("XGBoost Evaluation on Test Set:")
        print(classification_report(y_test, y_pred, target_names=class_labels))
    
    # ============ MODEL EVALUATION & COMPARISON ============
    def evaluate_model(model, X_te, y_te, label):
        preds = model.predict(X_te)
        metrics = {
            "model": label,
            "accuracy": accuracy_score(y_te, preds),
            "balanced_accuracy": balanced_accuracy_score(y_te, preds),
            "f1_macro": f1_score(y_te, preds, average="macro"),
            "f1_weighted": f1_score(y_te, preds, average="weighted"),
        }
        
        print(f"\n[{label}] Metrics:")
        for k, v in metrics.items():
            if k != "model":
                print(f"  {k}: {v:.4f}")
        
        return metrics
    
    results = []
    
    results.append(evaluate_model(logreg_base, X_test, y_test, "LogReg baseline"))
    results.append(evaluate_model(logreg_search.best_estimator_, X_test, y_test, "LogReg tuned"))
    results.append(evaluate_model(rf_search.best_estimator_, X_test, y_test, "RandomForest tuned"))
    
    if xgb_search is not None:
        results.append(evaluate_model(xgb_search.best_estimator_, X_test, y_test, "XGBoost tuned"))
    
    # ============ SAVE BEST MODEL ============
    results_df = pd.DataFrame(results).sort_values("f1_macro", ascending=False)
    print("\n=== Final Results ===")
    print(results_df)
    
    # Save best model
    MODELS_DIR = Path(models_dir)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    
    best_row = results_df.iloc[0]
    model_name = best_row["model"]
    
    if model_name == "LogReg baseline":
        best_model = logreg_base
    elif model_name == "LogReg tuned":
        best_model = logreg_search.best_estimator_
    elif model_name == "RandomForest tuned":
        best_model = rf_search.best_estimator_
    elif model_name == "XGBoost tuned":
        best_model = xgb_search.best_estimator_
    else:
        best_model = logreg_search.best_estimator_
    
    model_path = MODELS_DIR / "best_severity_model.joblib"
    joblib.dump(best_model, model_path)
    
    metrics_path = MODELS_DIR / "severity_metrics.json"
    metrics_path.write_text(json.dumps(results, indent=2))
    
    print("\n=== Model Saved ===")
    print("Saved model:", model_path)
    print("Saved metrics:", metrics_path)
    
    return {
        "best_model": best_model,
        "best_model_name": model_name,
        "results": results,
        "results_df": results_df,
        "model_path": str(model_path),
        "metrics_path": str(metrics_path),
    }

# def train_and_save_best_model(dataset_path: str, output_model_path: str, output_metrics_path: str = "models/severity_metrics.json"):
#     df = pd.read_csv(dataset_path, low_memory=False)

#     # Normalize severity
#     sev = df.get("severity", pd.Series([None] * len(df))).astype(str).str.lower().str.strip()
#     sev = sev.map({"low": "low", "medium": "medium", "med": "medium", "high": "high", "critical": "critical", "crit": "critical"})
#     valid = {"low", "medium", "high", "critical"}
#     df = df.loc[sev.isin(valid)].copy()
#     df["severity"] = sev[sev.isin(valid)]

#     # Label encode target
#     label_encoder = LabelEncoder()
#     df["severity_encoded"] = label_encoder.fit_transform(df["severity"])
#     class_labels = list(label_encoder.classes_)

#     # Time features
#     if "@timestamp" in df.columns:
#         ts = pd.to_datetime(df["@timestamp"], errors="coerce")
#         df["hour"] = ts.dt.hour
#         df["dayofweek"] = ts.dt.dayofweek
#         df["month"] = ts.dt.month
#     else:
#         df["hour"] = df["dayofweek"] = df["month"] = np.nan

#     # Feature selection
#     text_candidates = ["rule.description", "data.win.eventdata.commandLine", "raw", "rule.mitre.id"]
#     cat_candidates = ["agent.name", "location", "agent.id", "rule.id"]
#     num_candidates = ["hour", "dayofweek", "month"]
#     existing = set(df.columns)
#     text_cols = [c for c in text_candidates if c in existing]
#     cat_cols = [c for c in cat_candidates if c in existing]
#     num_cols = [c for c in num_candidates if c in existing]

#     # Clean text
#     for c in text_cols:
#         df[c] = clean_text_series(df[c])

#     # Mask level leaks in raw
#     if "raw" in df.columns:
#         patterns = [
#             r'"level"\s*:\s*\d+',
#             r"'level'\s*:\s*\d+",
#             r'"severity"\s*:\s*"[a-zA-Z]+"',
#             r"'severity'\s*:\s*'[a-zA-Z]+'",
#             r'"rule"\s*:\s*\{[^}]*"level"\s*:\s*\d+[^}]*\}',
#             r"'rule'\s*:\s*\{[^}]*'level'\s*:\s*\d+[^}]*\}",
#         ]
#         raw_series = df["raw"].astype(str)
#         for pat in patterns:
#             raw_series = raw_series.str.replace(pat, "<MASK>", regex=True)
#         df["raw"] = raw_series

#     # Drop high-cardinality cat cols
#     max_card = 50
#     cat_cols = [c for c in cat_cols if df[c].nunique(dropna=True) <= max_card]

#     feature_cols = text_cols + cat_cols + num_cols
#     if not feature_cols:
#         raise ValueError("No usable feature columns found.")

#     X = df[feature_cols].copy()
#     y = df["severity_encoded"].copy()

#     # Split
#     X_train, X_test, y_train, y_test = train_test_split(
#         X, y, test_size=0.2, random_state=SEED, stratify=y
#     )
#     cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=SEED)

#     # Pipelines
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
#     num_pipeline = Pipeline([
#         ("imputer", num_imputer),
#         ("scaler", StandardScaler(with_mean=False)),
#     ])

#     transformers = []
#     if text_cols: transformers.append(("text", text_pipeline, text_cols))
#     if cat_cols:  transformers.append(("cat", cat_pipeline, cat_cols))
#     if num_cols:  transformers.append(("num", num_pipeline, num_cols))

#     preprocess = ColumnTransformer(transformers)

#     logreg = Pipeline([
#         ("preprocess", preprocess),
#         ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", solver="liblinear")),
#     ])

#     # Fit
#     logreg.fit(X_train, y_train)

#     # Evaluate
#     y_pred = logreg.predict(X_test)
#     f1_macro = f1_score(y_test, y_pred, average="macro")
#     print("F1_macro (LogReg tuned-ish):", f1_macro)
#     print(classification_report(y_test, y_pred, target_names=class_labels))

#     # Save model payload with extras
#     payload = {
#         "model": logreg,
#         "feature_cols": feature_cols,
#         "class_labels": class_labels,
#         "label_encoder": label_encoder,
#     }
#     out_path = Path(output_model_path)
#     out_path.parent.mkdir(parents=True, exist_ok=True)
#     joblib.dump(payload, out_path)

#     metrics = {"f1_macro": f1_macro, "class_labels": class_labels}
#     Path(output_metrics_path).parent.mkdir(parents=True, exist_ok=True)
#     Path(output_metrics_path).write_text(json.dumps(metrics, indent=2))

#     print("Saved model:", out_path)
#     print("Saved metrics:", output_metrics_path)
#     return str(out_path), metrics


