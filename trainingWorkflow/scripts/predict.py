#!/usr/bin/env python
"""Predict severity and attack_type from raw Wazuh logs."""
from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import List

import numpy as np
import pandas as pd
import joblib

TEXT_COLUMNS: List[str] = [
    "rule.description",
    "raw",
    "data.win.eventdata.commandLine",
    "location",
    "rule.id",
    "agent.name",
    "agent.id",
]


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )


def add_features(frame: pd.DataFrame) -> pd.DataFrame:
    df_local = frame.copy()

    if "@timestamp" in df_local.columns:
        ts = pd.to_datetime(df_local["@timestamp"], errors="coerce")
        df_local["hour"] = ts.dt.hour
        df_local["dayofweek"] = ts.dt.dayofweek
        df_local["month"] = ts.dt.month
    else:
        df_local["hour"] = np.nan
        df_local["dayofweek"] = np.nan
        df_local["month"] = np.nan

    available = [col for col in TEXT_COLUMNS if col in df_local.columns]
    if available:
        df_local["text_global"] = (
            df_local[available]
            .fillna("")
            .astype(str)
            .agg(" ".join, axis=1)
            .str.replace(r"\s+", " ", regex=True)
            .str.strip()
        )
    else:
        df_local["text_global"] = ""
    return df_local


def build_feature_cols(df: pd.DataFrame) -> List[str]:
    feature_cols = ["text_global", "hour", "dayofweek", "month"]
    if "rule.level" in df.columns:
        feature_cols.append("rule.level")
    return feature_cols


def max_score(model, X: pd.DataFrame) -> np.ndarray | None:
    if hasattr(model, "predict_proba"):
        scores = model.predict_proba(X)
        return scores.max(axis=1)
    if hasattr(model, "decision_function"):
        scores = model.decision_function(X)
        scores = np.asarray(scores)
        if scores.ndim == 1:
            return np.abs(scores)
        return scores.max(axis=1)
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Predict severity and attack_type from Wazuh logs.")
    parser.add_argument("--input", type=Path, required=True, help="Input CSV path.")
    parser.add_argument("--output", type=Path, required=True, help="Output CSV path.")
    return parser.parse_args()


def main() -> None:
    configure_logging()
    args = parse_args()

    base_dir = Path(__file__).resolve().parents[1]
    models_dir = base_dir / "models"
    severity_model_path = models_dir / "severity_model.joblib"
    attack_model_path = models_dir / "attack_type_model.joblib"

    if not args.input.exists():
        raise FileNotFoundError(f"Input file not found: {args.input}")
    if not severity_model_path.exists() or not attack_model_path.exists():
        raise FileNotFoundError("Missing models in trainingWorkflow/models/")

    df = pd.read_csv(args.input, low_memory=False)
    df_feat = add_features(df)
    feature_cols = build_feature_cols(df_feat)
    X_pred = df_feat[feature_cols]

    sev_model = joblib.load(severity_model_path)
    atk_model = joblib.load(attack_model_path)

    output = df.copy()
    output["severity_pred"] = sev_model.predict(X_pred)
    output["attack_type_pred"] = atk_model.predict(X_pred)

    sev_score = max_score(sev_model, X_pred)
    atk_score = max_score(atk_model, X_pred)
    if sev_score is not None:
        output["severity_score"] = sev_score
    if atk_score is not None:
        output["attack_type_score"] = atk_score

    args.output.parent.mkdir(parents=True, exist_ok=True)
    output.to_csv(args.output, index=False)
    logging.info("Predictions saved to %s", args.output)


if __name__ == "__main__":
    main()
