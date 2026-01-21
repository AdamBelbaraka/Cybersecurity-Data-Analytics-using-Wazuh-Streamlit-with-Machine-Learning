import os
import sys
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from pipeline1 import ingest_csv_and_dump, train_and_save_best_model, CUSTOM_INDEX
from pipeline2 import run_prediction_cycle



# ==========================================================
# CONFIGURATION 
# ==========================================================

CSV_FILE = os.getenv("CSV_FILE", "wazuh_logs.csv")

EXPORT_PATH = os.getenv("EXPORT_PATH", "exports/index_dump_auto.csv")
MODEL_PATH = os.getenv("MODEL_PATH", "models/best_severity_model.joblib")
METRICS_PATH = os.getenv("METRICS_PATH", "models/severity_metrics.json")

BASE_URL = os.getenv("WAZUH_INDEXER_URL", "https://192.168.56.104:9200")
USERNAME = os.getenv("WAZUH_INDEXER_USER", "admin")
PASSWORD = os.getenv("WAZUH_INDEXER_PASS", "adminAdmin1*")

SOURCE_INDEX = os.getenv("SOURCE_INDEX", "wazuh-archives-4.x-*")
LOG_PATH = os.getenv("LOG_PATH", "ml_predictions_full.log")

SIZE = int(os.getenv("PREDICT_BATCH_SIZE", 500))
LAST_HOURS = int(os.getenv("LAST_HOURS", 4))


# ===================================
# LOGGING SYSTEM
# ===================================

def setup_logging():
    Path("logs").mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        handlers=[
            logging.FileHandler("logs/pipeline_run.log", encoding="utf-8"),
            logging.StreamHandler(sys.stdout)
        ]
    )


# ===================================
# UTILS
# ===================================

def ensure_folders():
    Path("exports").mkdir(parents=True, exist_ok=True)
    Path("models").mkdir(parents=True, exist_ok=True)
    Path("logs").mkdir(parents=True, exist_ok=True)


def check_file_exists(path, label):
    if not Path(path).exists():
        logging.error(f" -  {label} introuvable : {path}")
        sys.exit(1)
    logging.info(f" - {label} trouvé : {path}")


# ===================================
# MAIN PIPELINE
# ===================================

def main():
    setup_logging()
    ensure_folders()

    logging.info("======================================")
    logging.info(" DÉMARRAGE PIPELINE AUTOMATISÉ")
    logging.info("======================================")

    # -------------------------------
    # Étape 1 : Vérifier CSV
    # -------------------------------
    check_file_exists(CSV_FILE, "CSV d'entrée")

    # -------------------------------
    # Étape 2 : Ingestion + dump dataset
    # -------------------------------
    logging.info("-  Étape 1/3 : Ingestion CSV + export dataset...")
    ingest_csv_and_dump(
        CSV_FILE=CSV_FILE,
        index_name=CUSTOM_INDEX,
        output_path=EXPORT_PATH
    )
    check_file_exists(EXPORT_PATH, "Dataset exporté")

    # -------------------------------
    # Étape 3 : Entraînement ML
    # -------------------------------
    logging.info("-  Étape 2/3 : Entraînement ML...")
    model_path, metrics = train_and_save_best_model(
        dataset_path=EXPORT_PATH,
        output_model_path=MODEL_PATH,
        output_metrics_path=METRICS_PATH,
    )

    check_file_exists(model_path, "Modèle ML sauvegardé")
    check_file_exists(METRICS_PATH, "Métriques sauvegardées")

    logging.info(f" - Modèle entraîné et sauvegardé : {model_path}")
    logging.info(f" - Métriques : {json.dumps(metrics, indent=2)}")

    # -------------------------------
    # Étape 4 : Prédiction Wazuh
    # -------------------------------
    logging.info("-  Étape 3/3 : Prédiction sur Wazuh Indexer...")

    last_ts = (datetime.utcnow() - timedelta(hours=LAST_HOURS)).isoformat()

    preds = run_prediction_cycle(
        model_path=model_path,
        base_url=BASE_URL,
        username=USERNAME,
        password=PASSWORD,
        source_index=SOURCE_INDEX,
        log_path=LOG_PATH,
        last_ts=last_ts,
        size=SIZE,
    )

    logging.info(f" - Nombre de prédictions réalisées : {len(preds)}")

    logging.info("======================================")
    logging.info("-  PIPELINE TERMINÉ AVEC SUCCÈS")
    logging.info("======================================")

    print("\n -  Résumé :")
    print(f"- Dataset exporté : {EXPORT_PATH}")
    print(f"- Modèle : {MODEL_PATH}")
    print(f"- Métriques : {METRICS_PATH}")
    print(f"- Logs prédiction : {LOG_PATH}")


if __name__ == "__main__":
    main()
