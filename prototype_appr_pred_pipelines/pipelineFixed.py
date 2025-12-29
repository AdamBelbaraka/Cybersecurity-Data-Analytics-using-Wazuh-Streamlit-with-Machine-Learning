import requests
import pandas as pd
import json
import time
import random
from datetime import datetime, timezone
from requests.auth import HTTPBasicAuth

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
SIM_ARCHIVES_INDEX = "wazuh-archives-4.x-sim"

CSV_FILE = "wazuh_alerts_20251229_000057.csv"
CSV_CHUNK_SIZE = 1000

LOCAL_LOG_FILE = r"C:\Users\Lenovo\Documents\ml_predictions.log"
POLL_INTERVAL = 10

requests.packages.urllib3.disable_warnings()
auth = HTTPBasicAuth(USERNAME, PASSWORD)

# ==========================================================
# INDEXER CONNECTIVITY
# ==========================================================

print("🔍 Checking Indexer connectivity...")
resp = requests.get(BASE_URL, auth=auth, headers=HEADERS, verify=False)
resp.raise_for_status()
print("✔ Indexer reachable")

# ==========================================================
# RECREATE ML INDEX (CLEAN START)
# ==========================================================

print(f"🧹 Deleting index '{CUSTOM_INDEX}' if it exists...")
delete_resp = requests.delete(f"{BASE_URL}/{CUSTOM_INDEX}", auth=auth, headers=HEADERS, verify=False)

if delete_resp.status_code not in [200, 404]:
    raise RuntimeError(f"Error deleting index: {delete_resp.text}")

print("✔ Index deleted or did not exist")

# Create fresh index with mapping
print(f"🔧 Creating clean index '{CUSTOM_INDEX}' with mapping...")
mapping = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
    },
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "event_type": {"type": "keyword"},
            "ml_label": {"type": "keyword"},
            "risk_score": {"type": "float"},
            "ml_model": {"type": "keyword"},
            "agent": {
                "properties": {
                    "id": {"type": "keyword"},
                    "name": {"type": "keyword"}
                }
            }
        }
    }
}

create_resp = requests.put(
    f"{BASE_URL}/{CUSTOM_INDEX}",
    auth=auth,
    headers=HEADERS,
    json=mapping,
    verify=False
)

create_resp.raise_for_status()
print("✔ Index created")

# ==========================================================
# BULK INGEST CSV DATA → ML INDEX
# ==========================================================

def bulk_index_dataframe(df, index_name):
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
        verify=False
    )

    resp.raise_for_status()

    bulk_result = resp.json()
    if bulk_result.get("errors"):
        # Extract first error
        for item in bulk_result["items"]:
            if "error" in item["index"]:
                raise RuntimeError(json.dumps(item["index"]["error"], indent=2))

total_rows_injected = 0
print("📥 Bulk-ingesting CSV dataset...")

for chunk in pd.read_csv(CSV_FILE, chunksize=CSV_CHUNK_SIZE):
    bulk_index_dataframe(chunk, CUSTOM_INDEX)
    total_rows_injected += len(chunk)
    time.sleep(0.2)

# Refresh after ingestion to make documents searchable immediately
requests.post(f"{BASE_URL}/{CUSTOM_INDEX}/_refresh", auth=auth, headers=HEADERS, verify=False)

print(f"✔ CSV data indexed ({total_rows_injected} rows)")

# ==========================================================
# RETRIEVE FULL DATASET → DATAFRAME (SCROLL API)
# ==========================================================

def scroll_all(index, size=1000, scroll="2m"):
    docs = []

    query = {"size": size, "query": {"match_all": {}}}
    resp = requests.post(
        f"{BASE_URL}/{index}/_search?scroll={scroll}",
        auth=auth,
        headers=HEADERS,
        json=query,
        verify=False
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
            verify=False
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
            verify=False
        )

    return pd.DataFrame(docs)

print("📊 Retrieving ML dataset...")
df_indexed = scroll_all(CUSTOM_INDEX)
rows_retrieved = len(df_indexed)

print(df_indexed.head())
print(f"✔ Rows retrieved from index: {rows_retrieved}")

if rows_retrieved == total_rows_injected:
    print("✅ Data verification passed: all injected rows retrieved")
else:
    print(f"⚠️ Data verification mismatch: injected={total_rows_injected}, retrieved={rows_retrieved}")

# ==========================================================
# ML PREDICTION SIMULATION
# ==========================================================

def run_prediction(event):
    score = round(random.uniform(0, 1), 3)
    label = "malicious" if score > 0.7 else "benign"

    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "ml_prediction",
        "ml_label": label,
        "risk_score": score,
        "ml_model": "baseline_random_v1",
        "agent": {"id": "001", "name": "WIN10-LAB"}
    }

def write_prediction(pred):
    with open(LOCAL_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(pred) + "\n")

# ==========================================================
# SIMULATE WAZUH ARCHIVE EVENTS
# ==========================================================

def send_simulated_archive_events(events):
    lines = []
    for ev in events:
        lines.append(json.dumps({"index": {"_index": SIM_ARCHIVES_INDEX}}))
        lines.append(json.dumps(ev))

    payload = "\n".join(lines) + "\n"

    resp = requests.post(
        f"{BASE_URL}/_bulk",
        auth=auth,
        headers={"Content-Type": "application/x-ndjson"},
        data=payload.encode("utf-8"),
        verify=False
    )
    resp.raise_for_status()

# ==========================================================
# POLLING WAZUH ARCHIVES
# ==========================================================

def poll_new_events(last_ts):
    query = {
        "size": 100,
        "sort": [{"@timestamp": "asc"}],
        "query": {"range": {"@timestamp": {"gt": last_ts}}}
    }

    resp = requests.post(
        f"{BASE_URL}/{SOURCE_INDEX}/_search",
        auth=auth,
        headers=HEADERS,
        json=query,
        verify=False
    )
    resp.raise_for_status()
    return resp.json()["hits"]["hits"]

# ==========================================================
# MAIN LOOP
# ==========================================================

print("🚀 Starting ML listening pipeline...")
last_seen_ts = datetime.now(timezone.utc).isoformat()

atomic_sim_events = [
    {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "atomic_red_team",
        "tactic": "execution",
        "technique_id": "T1059.001",
        "command": "powershell.exe -enc SQBFAFgA",
        "host": {"name": "WIN10-LAB"},
        "user": {"name": "Administrator"}
    }
]

# Reset predictions log
open(LOCAL_LOG_FILE, "w").close()
predictions_written = 0

while True:
    try:
        send_simulated_archive_events(atomic_sim_events)

        hits = poll_new_events(last_seen_ts)

        if hits:
            print(f"🟢 {len(hits)} new events")

            for hit in hits:
                src = hit["_source"]

                pred = run_prediction(src)
                write_prediction(pred)
                predictions_written += 1

                # Update last timestamp
                last_seen_ts = src["@timestamp"]

                print(f"➡ ML | score={pred['risk_score']} label={pred['ml_label']}")

            # Verification step
            with open(LOCAL_LOG_FILE, "r", encoding="utf-8") as f:
                predictions_file_lines = sum(1 for _ in f)

            if predictions_file_lines == predictions_written:
                print(f"✅ Predictions verification passed: {predictions_written} written")
            else:
                print(f"⚠️ Predictions mismatch: expected={predictions_written}, file={predictions_file_lines}")

    except Exception as e:
        print("❌ Error:", e)

    time.sleep(POLL_INTERVAL)