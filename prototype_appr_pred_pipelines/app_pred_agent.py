import requests
import pandas as pd
import json
import os
import random
from datetime import datetime,  timezone
from requests.auth import HTTPBasicAuth
import time 
# -----------------------------
# Configuration
# -----------------------------
INDEXER_IP = "192.168.56.104"
INDEXER_PORT = 9200
USERNAME = "admin"
PASSWORD = "adminAdmin1*"
CUSTOM_INDEX = "wazuh-ml-data-0001"     # index dedicated to data to be processed by ml engine
BASE_URL = f"https://{INDEXER_IP}:{INDEXER_PORT}"
HEADERS = {"Content-Type": "application/json"}


requests.packages.urllib3.disable_warnings()

# =============================
# PIPELINE 1 — SIMULATION DATA
# =============================

# -----------------------------
# Step 1 — Connection Check (Indexer)
# -----------------------------
print("Checking connection to indexer...", end=" ")
resp = requests.get(BASE_URL, auth=(USERNAME, PASSWORD), headers=HEADERS, verify=False)
resp.raise_for_status()
print("✔ Success! Indexer reachable.")

# -----------------------------
# Step 2 — Ensure Index Exists
# -----------------------------
print(f"\nEnsuring index '{CUSTOM_INDEX}' exists...", end=" ")
exists_resp = requests.head(f"{BASE_URL}/{CUSTOM_INDEX}", auth=(USERNAME, PASSWORD), headers=HEADERS, verify=False)
if exists_resp.status_code == 404:
    create_resp = requests.put(f"{BASE_URL}/{CUSTOM_INDEX}", auth=(USERNAME, PASSWORD), headers=HEADERS, verify=False)
    assert create_resp.ok, f"Could not create index: {create_resp.text}"
    print("✔ Created.")
elif exists_resp.status_code == 200:
    print("✔ Already exists.")
else:
    raise RuntimeError(f"Index check error: {exists_resp.status_code}")

# -----------------------------
# Step 3 — Simulate Atomic Red Team Logs  and send data ( ndjson format ) to the ml data index
# -----------------------------
print("\nGenerating Atomic Red Team simulated logs...")
atomic_logs_json = [
    {
        "event_type": "atomic_red_team",
        "tactic": "execution",
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "command": "powershell.exe -enc SQBFAFgA",
        "platform": "windows",
        "executor": "command_prompt",
        "host": "WIN10-LAB",
        "user": "Administrator",
        "timestamp": pd.Timestamp.now().isoformat()
    },
    {
        "event_type": "atomic_red_team",
        "tactic": "credential_access",
        "technique_id": "T1003",
        "technique_name": "Credential Dumping",
        "command": "mimikatz.exe sekurlsa::logonpasswords",
        "platform": "windows",
        "executor": "powershell",
        "host": "WIN10-LAB",
        "user": "SYSTEM",
        "timestamp": pd.Timestamp.now().isoformat()
    }
]
print(f"✔ Generated {len(atomic_logs_json)} Atomic Red Team logs.")




with open("data.ndjson", "w") as f:
    for rec in atomic_logs_json:
        f.write(json.dumps({"index": {"_index": CUSTOM_INDEX}}) + "\n")
        f.write(json.dumps(rec) + "\n")

requests.post(
    f"{BASE_URL}/_bulk",
    auth=(USERNAME, PASSWORD),
    headers={"Content-Type": "application/x-ndjson"},
    data=open("data.ndjson","rb"),
    verify=False
)



# -----------------------------
# Step 5 — Retrieve to DataFrame  from ml index 
# -----------------------------
print(f"\nRetrieving documents from '{CUSTOM_INDEX}'…")
search_query = {"query": {"match_all": {}}}
search_resp = requests.get(
    f"{BASE_URL}/{CUSTOM_INDEX}/_search",
    auth=(USERNAME, PASSWORD),
    headers=HEADERS,
    data=json.dumps(search_query),
    verify=False
)
search_resp.raise_for_status()
hits = search_resp.json().get("hits", {}).get("hits", [])        #{ "hits":"hits": [ {"_index": "my_index", "_id": "1", "_source": {"field": "value1"}}, {"_index": "my_index", "_id": "2", "_source": {"field": "value2"}} ] } }
print("\nIndexed DataFrame:")
df_indexed = pd.DataFrame([hit["_source"] for hit in hits])        
print(df_indexed.head())

# ----------------------------- a integrer ici le ML pipeline d apprentissage : input = df_indexed , output = model.pkl




# =================================== Partie Prediction ==========================================

# =============================
# PIPELINE 2 — LISTENING + ML
# =============================

# Index source Wazuh à écouter (pas buffer)
SOURCE_INDEX = "wazuh-archives-4.x-*"

# Polling
POLL_INTERVAL = 10  # secondes

# Log local Windows (agent)
LOCAL_LOG_FILE = r"C:\Users\Lenovo\Documents\ml_predictions.log"


def poll_new_events(last_ts):
    """Récupère uniquement les nouveaux événements Wazuh"""
    query = {
        "size": 50,
        "sort": [{"@timestamp": "asc"}],
        "query": {
            "range": {
                "@timestamp": {
                    "gt": last_ts
                }
            }
        }
    }

    resp = requests.get(
        f"{BASE_URL}/{SOURCE_INDEX}/_search",
        auth=(USERNAME, PASSWORD),
        headers=HEADERS,
        json=query,
        verify=False
    )
    resp.raise_for_status()
    return resp.json()["hits"]["hits"]


 # a utiliser model.pkl  par la suite
def run_prediction(event): 
    """Pipeline ML simulé"""
    risk_score = round(random.uniform(0, 1), 3)
    label = "malicious" if risk_score > 0.7 else "benign"

    return {
        "integration": "ml-pipeline",
        "event_type": "ml_prediction",
        "ml_label": label,
        "risk_score": risk_score,
        "ml_model": "baseline_random_v1",
        "timestamp": datetime.now(timezone.utc).isoformat(),

        # Contexte Wazuh
        "host": event.get("host", {}).get("name", ""),
        "user": event.get("user", {}).get("name", ""),
        "technique_id": event.get("rule", {}).get("mitre", {}).get("id", ""),
        "tactic": event.get("rule", {}).get("mitre", {}).get("tactic", "")
    }
#  on peut aussi envoyer a un index ml-predict pour visualissations sur dashboards



# on ecrit les preds sur fichier local , l'agent wazuh transmet les predictions vers le manger ( meme processus de transmission de logs) => traitement par  decodeur implicite ( json) + regles definies sur manager 
def write_prediction(pred):
    """
    Écriture compatible Wazuh pour déclencher les règles
    """

    # to fix the event format expected by Wazuh rules
    # event = {
    #     "timestamp": pred["timestamp"],
    #     "event_type": "ml_prediction",  # déclenche 100100
    #     "ml_label": pred["ml_label"],   # déclenche 100110 si "malicious"
    #     "risk_score": pred["risk_score"],
    #     "ml_model": pred.get("ml_model", "baseline_random_v1"),
    #     "host": pred.get("host", "WIN-ML-AGENT"),
    #     "user": pred.get("user", ""),
    #     "tactic": pred.get("tactic", ""),
    #     "technique_id": pred.get("technique_id", "")
    # }

    # functional format 
    event = {
    "@timestamp": pred["timestamp"],
    "event_type": "ml_prediction",
    "ml_label": pred["ml_label"],
    "risk_score": pred["risk_score"],
    "ml_model": pred["ml_model"],

    "agent": {
        "id": "001",
        "name": "WIN10-LAB"
    }
    }
    


    # Écriture dans le fichier que l'agent lit
    with open(LOCAL_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


# =============================
# LOOP PRINCIPALE — LISTENING
# =============================

print("🚀 Starting ML listening pipeline...")
last_seen_ts = datetime.now(timezone.utc).isoformat()


# simuler l arrivee de logs sur manager 

# envoyons des events vers  index Wazuh SOURCE_INDEX = "wazuh-archives-4.x-*"  
SIM_ARCHIVES_INDEX = SOURCE_INDEX

print("📥 Injecting Atomic-style archive events...")

atomic_archives_events = [
    {
        "event_type": "atomic_red_team",
        "tactic": "execution",
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "command": "powershell.exe -enc SQBFAFgA",
        "platform": "windows",
        "executor": "command_prompt",
        "host": "WIN10-LAB",
        "user": "Administrator",
        "timestamp": pd.Timestamp.now().isoformat()
    },
    {
        "event_type": "atomic_red_team",
        "tactic": "credential_access",
        "technique_id": "T1003",
        "technique_name": "Credential Dumping",
        "command": "mimikatz.exe sekurlsa::logonpasswords",
        "platform": "windows",
        "executor": "powershell",
        "host": "WIN10-LAB",
        "user": "SYSTEM",
        "timestamp": pd.Timestamp.now().isoformat()
    }
]

def send_atomic_archive_events(events):
    with open("archives_sim.ndjson", "w") as f:
        for ev in atomic_archives_events:
            f.write(json.dumps({"index": {"_index": SIM_ARCHIVES_INDEX}}) + "\n")
            f.write(json.dumps(ev) + "\n")

    resp = requests.post(
        f"{BASE_URL}/_bulk",
        auth=(USERNAME, PASSWORD),
        headers={"Content-Type": "application/x-ndjson"},
        data=open("archives_sim.ndjson", "rb"),
        verify=False
    )

    print("✔ Simulated archive logs injected:", resp.status_code)

    requests.post(
        f"{BASE_URL}/{SIM_ARCHIVES_INDEX}/_refresh",
        auth=(USERNAME, PASSWORD),
        verify=False
    )
    return resp



print("🚀 Starting ML listening loop...")





while True:
    try:

        
        hits = poll_new_events(last_seen_ts)

        send_atomic_archive_events(atomic_archives_events)

        if hits:
            print(f"🟢 {len(hits)} new Wazuh events detected")

            for hit in hits:
                src = hit["_source"]

                prediction = run_prediction(src)
                write_prediction(prediction)

                print(
                    f"➡ Prediction | host={prediction['host']} "
                    f"score={prediction['risk_score']} "
                    f"label={prediction['ml_label']}"
                )

                # Mise à jour du curseur
                last_seen_ts = src["@timestamp"]

    except Exception as e:
        print("❌ Polling error:", e)

    time.sleep(POLL_INTERVAL)



