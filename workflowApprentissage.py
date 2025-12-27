


import requests
import pandas as pd
import json
import os

# -----------------------------
# Configuration
# -----------------------------
INDEXER_IP = "192.168.56.104"
INDEXER_PORT = 9200
USERNAME = "admin"
PASSWORD = "password"   # Update with your Wazuh indexer password
CUSTOM_INDEX = "wazuh-ml-predict-0001"
BASE_URL = f"https://{INDEXER_IP}:{INDEXER_PORT}"
HEADERS = {"Content-Type": "application/json"}

# CSV file (in current directory)
CSV_FILE = "phishing_emails.csv"

# Disable warnings for self-signed certs (lab only) !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
requests.packages.urllib3.disable_warnings()

# -----------------------------
# Step 1 — Connection Check
# -----------------------------
print("Checking connection to indexer...", end=" ")
try:
    resp = requests.get(
        BASE_URL,
        auth=(USERNAME, PASSWORD),
        headers=HEADERS,
        verify=False
    )
    resp.raise_for_status()
    print("✔ Success! Indexer reachable.")
except Exception as e:
    print("❌ Connection failed!")
    print(e)
    exit(1)

# -----------------------------
# Step 2 — Ensure Index Exists
# -----------------------------
print(f"\nEnsuring index '{CUSTOM_INDEX}' exists...", end=" ")
exists_resp = requests.head(
    f"{BASE_URL}/{CUSTOM_INDEX}",
    auth=(USERNAME, PASSWORD),
    headers=HEADERS,
    verify=False
)

if exists_resp.status_code == 404:
    create_resp = requests.put(
        f"{BASE_URL}/{CUSTOM_INDEX}",
        auth=(USERNAME, PASSWORD),
        headers=HEADERS,
        verify=False
    )
    if create_resp.ok:
        print("✔ Created.")
    else:
        print("❌ Could not create:", create_resp.text)
        exit(1)
elif exists_resp.status_code == 200:
    print("✔ Already exists.")
else:
    print("❌ Index check error:", exists_resp.status_code)
    exit(1)

# -----------------------------
# Step 3 — Read & Convert CSV
# -----------------------------
if not os.path.exists(CSV_FILE):
    print(f"❌ CSV file not found: {CSV_FILE}")
    exit(1)

print(f"\nReading '{CSV_FILE}'…")
df_csv = pd.read_csv(CSV_FILE)
print(f"✔ Loaded {len(df_csv)} rows.")

# Convert each row to dict
json_docs = df_csv.to_dict(orient="records")

# -----------------------------
# Step 4 — Index CSV Rows
# -----------------------------
# print("\nIndexing CSV rows…")

# for i, record in enumerate(json_docs):
#     # Optionally add a timestamp or index identifier
#     # record["indexed_at"] = pd.Timestamp.now().isoformat()

#     response = requests.post(
#         f"{BASE_URL}/{CUSTOM_INDEX}/_doc/",
#         auth=(USERNAME, PASSWORD),
#         headers=HEADERS,
#         data=json.dumps(record),
#         verify=False
#     )
#     if not response.ok:
#         print(f"⚠ Failed at row {i}: {response.status_code}")
#         print("Response:", response.text)

# print("✔ Finished indexing CSV rows.")


with open("data.ndjson", "w") as f:
    for rec in json_docs:
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
# Step 5 — Retrieve to DataFrame
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

if not search_resp.ok:
    print("❌ Search failed!")
    print(search_resp.status_code, search_resp.text)
    exit(1)

results = search_resp.json()
hits = results.get("hits", {}).get("hits", [])
rows = [hit["_source"] for hit in hits]
df_indexed = pd.DataFrame(rows)


print("\nIndexed DataFrame:")
print(df_indexed)





# -----------------------------
# Step 6 — Simulate ML Predictions
# -----------------------------
import random

print("\nSimulating ML predictions...")

df_indexed["risk_score"] = [round(random.uniform(0, 1), 3) for _ in range(len(df_indexed))]
df_indexed["ml_label"] = df_indexed["risk_score"].apply(
    lambda x: "malicious" if x > 0.7 else "benign"
)

print(df_indexed[["risk_score", "ml_label"]].head())


# ----------------------------- 
# Step 7 — Update Indexed Documents
print("\nUpdating indexed documents with ML predictions...")

ML_INDEX = "wazuh-ml-results-0001"


# -----------------------------
# Step 2 — Ensure Index Exists
# -----------------------------
print(f"\nEnsuring index '{ML_INDEX}' exists...", end=" ")
exists_resp = requests.head(
    f"{BASE_URL}/{ML_INDEX}",
    auth=(USERNAME, PASSWORD),
    headers=HEADERS,
    verify=False
)

if exists_resp.status_code == 404:
    create_resp = requests.put(
        f"{BASE_URL}/{ML_INDEX}",
        auth=(USERNAME, PASSWORD),
        headers=HEADERS,
        verify=False
    )
    if create_resp.ok:
        print("✔ Created.")
    else:
        print("❌ Could not create:", create_resp.text)
        exit(1)
elif exists_resp.status_code == 200:
    print("✔ Already exists.")
else:
    print("❌ Index check error:", exists_resp.status_code)
    exit(1)


# ++++++++++++++++++++ 



print("\nInjecting ML predictions into Wazuh indexer...")

for _, row in df_indexed.iterrows():
    ml_doc = {
        "source_index": CUSTOM_INDEX,
        "risk_score": row["risk_score"],
        "ml_label": row["ml_label"],
        "@timestamp": pd.Timestamp.now().isoformat()
    }

    requests.post(
        f"{BASE_URL}/{ML_INDEX}/_doc",
        auth=(USERNAME, PASSWORD),
        headers=HEADERS,
        data=json.dumps(ml_doc),
        verify=False
    )

print("✔ ML predictions injected.")


# ________________________________________________________________________________________________Partie 2 _______________________________________________________________________________________________
#  ++++++++++++++++++++++ regle wazuh +++++++++++++++++++++++++++++++

