#!/usr/bin/env python
"""Applique le modele de severite (.pkl) sur simulate.csv et ecrit simulate_predictions.csv."""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import joblib


def combine_text(x):
    if hasattr(x, "fillna"):
        return x.fillna("").astype(str).agg(" ".join, axis=1)
    return pd.DataFrame(x).fillna("").astype(str).agg(" ".join, axis=1)


def to_dense_matrix(x):
    return x.toarray() if hasattr(x, "toarray") else x


def main() -> None:
    base_dir = Path(__file__).resolve().parent
    input_path = base_dir / "simulate.csv"
    output_path = base_dir / "simulate_predictions.csv"
    model_path = base_dir / "models" / "best_severity_model.pkl"

    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    if not model_path.exists():
        raise FileNotFoundError(f"Model file not found: {model_path}")

    model = joblib.load(model_path)
    raw = pd.read_csv(input_path, low_memory=False)

    # Add timestamp-derived features for prediction, but do not keep them in output
    if "@timestamp" in raw.columns:
        ts = pd.to_datetime(raw["@timestamp"], errors="coerce")
        raw["hour"] = ts.dt.hour
        raw["dayofweek"] = ts.dt.dayofweek
        raw["month"] = ts.dt.month
    else:
        raw["hour"] = np.nan
        raw["dayofweek"] = np.nan
        raw["month"] = np.nan

    preds = model.predict(raw)
    preds_series = pd.Series(preds)
    if preds_series.dtype.kind in {"i", "u"}:
        class_labels = ["critical", "high", "low", "medium"]
        preds_series = preds_series.map(
            lambda idx: class_labels[int(idx)] if int(idx) < len(class_labels) else "unknown"
        )
    else:
        preds_series = preds_series.astype(str)

    out = raw.copy()
    out["severity_pred"] = preds_series
    out = out.drop(columns=["hour", "dayofweek", "month"], errors="ignore")

    out.to_csv(output_path, index=False)
    print(f"Saved predictions to: {output_path}")


if __name__ == "__main__":
    main()
