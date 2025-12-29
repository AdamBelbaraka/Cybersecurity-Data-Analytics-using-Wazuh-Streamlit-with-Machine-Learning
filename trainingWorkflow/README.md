# Training workflow

This workflow builds labels from Wazuh logs, trains two models (severity and attack_type),
and generates predictions from raw logs.

Prerequisites
- Python 3.9+
- pandas, numpy, scikit-learn, joblib
- Optional: xgboost, lightgbm, imbalanced-learn

Step 1 - Build labeled dataset
```bash
python scripts/build_labeled_dataset.py --input data/last_wazuh.csv --output data/labeled_logs.csv
```

What it does
- Adds severity from rule.level (configurable in the script)
- Uses rule.mitre.id when present, otherwise infers the closest MITRE id by TF-IDF similarity
- Writes data/labeled_logs.csv and prints a summary (rows, severity distribution, UNKNOWN rate)

Step 2 - Train models (notebook)
- Open and run: notebooks/preprocessing.ipynb
- The notebook performs EDA, builds a robust preprocessing pipeline, trains and evaluates models,
  and exports artifacts to models/
- Saved files:
  - models/severity_model.joblib
  - models/attack_type_model.joblib
  - models/metadata.json

Step 3 - Predict on raw logs
```bash
python scripts/predict.py --input data/last_wazuh.csv --output data/predictions.csv
```

Output columns
- severity_pred, attack_type_pred
- severity_score and attack_type_score when probabilities or decision scores are available

Notes
- The pipeline is robust to missing columns in input CSVs.
- Timestamp features: hour, dayofweek, month.
- Text features are built from available columns (rule.description, raw, commandLine, location, etc.).


