import requests
import csv
import time
from datetime import datetime, timezone, timedelta
import json
import argparse

# Default configurations
# CREDENTIALS_FILE = 'credentials-7d8ef4-2025-Jun-03--19_04_32.csv'
CREDENTIALS_FILE = '8180.csv'

# 8.15.5
# ENDPOINT = 'https://422d8d8900294219b0768d9951b44b05.asia-northeast1.gcp.cloud.es.io/'
# 8.18.0
ENDPOINT = 'https://c9c767b07f2540b29168b7d0e0377c92.asia-northeast1.gcp.cloud.es.io'

# Read credentials
def get_credentials(filename):
    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        row = next(reader)
        return row['username'], row['password']

# Parse command-line arguments
def parse_args():
    parser = argparse.ArgumentParser(description="Bulk software/threat inventory to Elasticsearch.")
    parser.add_argument('--endpoint', type=str, default=ENDPOINT, help='Elasticsearch bulk endpoint URL')
    parser.add_argument('--credentials', type=str, default=CREDENTIALS_FILE, help='CSV file with username/password')
    return parser.parse_args()

args = parse_args()
ENDPOINT = args.endpoint
CREDENTIALS_FILE = args.credentials
username, password = get_credentials(CREDENTIALS_FILE)

# Example software data
software_list = [
    {"software": "python", "version": "3.10"},
    {"software": "python", "version": "2.7"},
    {"software": "python", "version": "3.8"},
    {"software": "node.js", "version": "18.17"},
    {"software": "node.js", "version": "16.15"},
    {"software": "node.js", "version": "20.5"},
]

# Example threat indicator data (EOL versions)
threat_list = [
    {"threat.indicator.software": "python", "threat.indicator.version": "3.10"},
    {"threat.indicator.software": "node.js", "threat.indicator.version": "18.17"}
]

headers = {'Content-Type': 'application/x-ndjson'}

def make_bulk_payload(software, is_threat=False):
    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    if is_threat:
        index_cmd = '{ "index": { "_index": "eol-versions" } }'
        doc = {
            **software,
            "@timestamp": now
        }
    else:
        index_cmd = '{ "index": { "_index": "software" } }'
        doc = {
            **software,
            "@timestamp": now,
            "event": {"category": "software_inventory"}
        }
    return f"{index_cmd}\n{json.dumps(doc)}"

def print_eol_bulk():
    print("POST _bulk")
    now = datetime.now(timezone.utc)
    for i, threat in enumerate(threat_list):
        timestamp = (now + timedelta(seconds=i*10)).strftime('%Y-%m-%dT%H:%M:%SZ')
        print('{ "index": { "_index": "eol-versions" } }')
        doc = dict(threat)
        doc["@timestamp"] = timestamp
        print(json.dumps(doc, separators=(",", ": ")))

def main():
    # Send all threat indicator documents (eol-versions) just once (bootstrap)
    bulk_endpoint = ENDPOINT.rstrip('/') + '/_bulk'
    for i, threat in enumerate(threat_list):
        payload = make_bulk_payload(threat, is_threat=True) + '\n'
        print_type = 'threat-bootstrap'
        response = requests.post(
            bulk_endpoint,
            data=payload,
            headers=headers,
            auth=(username, password)
        )
        print(f"Sent ({print_type}): {payload.strip()}\nStatus: {response.status_code}, Response: {response.text[:200]}")
    # Then loop sending software data only
    i = 0
    while True:
        software = software_list[i % len(software_list)]
        payload = make_bulk_payload(software) + '\n'
        print_type = 'software'
        response = requests.post(
            bulk_endpoint,
            data=payload,
            headers=headers,
            auth=(username, password)
        )
        print(f"Sent ({print_type}): {payload.strip()}\nStatus: {response.status_code}, Response: {response.text[:200]}")
        i += 1
        time.sleep(30)

if __name__ == "__main__":
    main()
