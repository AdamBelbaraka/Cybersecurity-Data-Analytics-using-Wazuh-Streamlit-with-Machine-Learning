#!/usr/bin/env python
"""Build a labeled dataset from Wazuh logs."""
from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

SEVERITY_RULES: Sequence[Tuple[int, int, str]] = (
    (0, 3, "low"),
    (4, 6, "medium"),
    (7, 10, "high"),
    (11, 15, "critical"),
)
DEFAULT_SEVERITY = "low"
MITRE_SIM_THRESHOLD = 0.25

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


def build_text_global(df: pd.DataFrame, columns: Iterable[str]) -> pd.Series:
    available = [col for col in columns if col in df.columns]
    if not available:
        return pd.Series([""] * len(df), index=df.index)
    return (
        df[available]
        .fillna("")
        .astype(str)
        .agg(" ".join, axis=1)
        .str.replace(r"\s+", " ", regex=True)
        .str.strip()
    )


def map_severity(levels: pd.Series) -> Tuple[pd.Series, int]:
    levels_numeric = pd.to_numeric(levels, errors="coerce")
    severity = pd.Series([DEFAULT_SEVERITY] * len(levels_numeric), index=levels_numeric.index)
    for min_level, max_level, label in SEVERITY_RULES:
        mask = levels_numeric.between(min_level, max_level, inclusive="both")
        severity.loc[mask] = label
    missing_count = int(levels_numeric.isna().sum())
    return severity, missing_count


def infer_attack_type(
    df: pd.DataFrame,
    text_global: pd.Series,
    mitre_col: str,
    threshold: float,
) -> Tuple[pd.Series, pd.Series, float]:
    if mitre_col not in df.columns:
        attack_type = pd.Series(["UNKNOWN"] * len(df), index=df.index)
        scores = pd.Series([0.0] * len(df), index=df.index)
        return attack_type, scores, 0.0

    mitre_series = df[mitre_col].fillna("").astype(str).str.strip()
    has_mitre = mitre_series != ""
    attack_type = mitre_series.where(has_mitre, "")
    scores = pd.Series([0.0] * len(df), index=df.index)

    if has_mitre.sum() == 0:
        attack_type[:] = "UNKNOWN"
        return attack_type, scores, 0.0

    profiles = (
        pd.DataFrame({"mitre": mitre_series[has_mitre], "text": text_global[has_mitre]})
        .groupby("mitre")["text"]
        .apply(lambda items: " ".join(items.tolist()))
    )
    if profiles.empty or profiles.str.strip().eq("").all():
        attack_type[~has_mitre] = "UNKNOWN"
        return attack_type, scores, 0.0

    vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=5000)
    try:
        profile_matrix = vectorizer.fit_transform(profiles.values)
    except ValueError:
        attack_type[~has_mitre] = "UNKNOWN"
        return attack_type, scores, 0.0

    missing_mask = ~has_mitre
    if missing_mask.sum() == 0:
        return attack_type, scores, 0.0

    missing_text = text_global[missing_mask].fillna("").astype(str)
    missing_matrix = vectorizer.transform(missing_text.values)
    similarity = cosine_similarity(missing_matrix, profile_matrix)
    best_idx = similarity.argmax(axis=1)
    best_scores = similarity.max(axis=1)
    profile_ids = profiles.index.to_list()

    inferred = []
    inferred_scores = []
    for idx, score in zip(best_idx, best_scores):
        if score >= threshold:
            inferred.append(profile_ids[int(idx)])
            inferred_scores.append(float(score))
        else:
            inferred.append("UNKNOWN")
            inferred_scores.append(float(score))

    attack_type.loc[missing_mask] = inferred
    scores.loc[missing_mask] = inferred_scores
    return attack_type, scores, float(np.mean(best_scores)) if len(best_scores) else 0.0


def print_summary(df: pd.DataFrame, severity_missing: int) -> None:
    total = len(df)
    severity_counts = df["severity"].value_counts(dropna=False)
    unknown_pct = (df["attack_type"].eq("UNKNOWN").mean() * 100) if total else 0.0

    logging.info("Rows: %s", total)
    logging.info("Severity distribution:\n%s", severity_counts.to_string())
    logging.info("Severity missing levels defaulted to '%s': %s", DEFAULT_SEVERITY, severity_missing)
    logging.info("Attack type UNKNOWN: %.2f%%", unknown_pct)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Label Wazuh logs with severity and attack_type.")
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Input CSV path (default: trainingWorkflow/data/last_wazuh.csv).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output CSV path (default: trainingWorkflow/data/labeled_logs.csv).",
    )
    parser.add_argument(
        "--mitre-threshold",
        type=float,
        default=MITRE_SIM_THRESHOLD,
        help="Cosine similarity threshold for inferred MITRE mapping.",
    )
    return parser.parse_args()


def main() -> None:
    configure_logging()
    args = parse_args()

    base_dir = Path(__file__).resolve().parents[1]
    input_path = args.input or (base_dir / "data" / "last_wazuh.csv")
    output_path = args.output or (base_dir / "data" / "labeled_logs.csv")

    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    logging.info("Loading %s", input_path)
    df = pd.read_csv(input_path, low_memory=False)

    text_global = build_text_global(df, TEXT_COLUMNS)

    if "rule.level" in df.columns:
        severity, missing_count = map_severity(df["rule.level"])
    else:
        severity = pd.Series([DEFAULT_SEVERITY] * len(df), index=df.index)
        missing_count = len(df)
        logging.warning("Column rule.level missing. Defaulting all severities to '%s'.", DEFAULT_SEVERITY)

    df["severity"] = severity

    attack_type, scores, avg_score = infer_attack_type(
        df,
        text_global=text_global,
        mitre_col="rule.mitre.id",
        threshold=args.mitre_threshold,
    )
    df["attack_type"] = attack_type

    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)

    logging.info("Saved labeled dataset to %s", output_path)
    logging.info("Average inferred similarity score (missing mitre): %.4f", avg_score)
    print_summary(df, missing_count)


if __name__ == "__main__":
    main()
