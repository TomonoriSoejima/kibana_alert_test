import requests
import csv
import time
from datetime import datetime, timezone, timedelta
import json
import argparse
import os

# Default configurations
# CREDENTIALS_FILE = 'credentials-7d8ef4-2025-Jun-03--19_04_32.csv'
CREDENTIALS_FILE = 'v7.csv'

CLOUD_API_BASE = 'https://api.elastic-cloud.com/api/v1'

# Load CLOUD_API_KEY from .env file if present, otherwise fall back to environment variable
def load_cloud_api_key():
    env_file = os.path.join(os.path.dirname(__file__), '.env')
    if os.path.exists(env_file):
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line.startswith('ELASTIC_CLOUD_API_KEY='):
                    return line.split('=', 1)[1].strip()
    key = os.environ.get('ELASTIC_CLOUD_API_KEY')
    if not key:
        raise SystemExit('ELASTIC_CLOUD_API_KEY not set. Add it to .env or set as environment variable.')
    return key

CLOUD_API_KEY = load_cloud_api_key()

# Read credentials
def get_credentials(filename):
    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        row = next(reader)
        return row['username'], row['password']

# Discover deployment ID from Elastic Cloud API by testing ES credentials
def discover_deployment_id(cloud_api_key):
    hdrs = {
        'Authorization': f'ApiKey {cloud_api_key}',
        'Content-Type': 'application/json',
    }
    resp = requests.get(CLOUD_API_BASE + '/deployments', headers=hdrs, timeout=10)
    resp.raise_for_status()
    deployments = resp.json().get('deployments', [])
    if not deployments:
        raise RuntimeError("No deployments found for this Cloud API key")
    print(f"Found {len(deployments)} deployment(s): {[d.get('name', d['id']) for d in deployments]}")
    # Try credentials against each deployment's ES endpoint to find the matching one
    for dep in deployments:
        dep_id = dep['id']
        r2 = requests.get(CLOUD_API_BASE + f'/deployments/{dep_id}', headers=hdrs, timeout=10)
        es_resources = r2.json().get('resources', {}).get('elasticsearch', [])
        if not es_resources:
            continue
        metadata = es_resources[0].get('info', {}).get('metadata', {})
        es_url = metadata.get('aliased_url') or metadata.get('service_url')
        if not es_url:
            continue
        try:
            test = requests.get(es_url.rstrip('/'), auth=(username, password), timeout=10)
            if test.status_code == 200:
                print(f"Matched deployment: {dep_id} ({dep.get('name', '')}) -> {es_url}")
                return dep_id
        except Exception:
            continue
    # Fall back to first deployment if none matched
    dep = deployments[0]
    print(f"No credential match found, falling back to first deployment: {dep['id']} ({dep.get('name', '')})")
    return dep['id']

# Discover Elasticsearch endpoint from Elastic Cloud API (apm-oneclick pattern)
def discover_es_endpoint(deployment_id, cloud_api_key):
    candidate_paths = [
        f"/deployments/{deployment_id}/elasticsearch/main-elasticsearch/_info",
        f"/deployments/{deployment_id}/elasticsearch/main-elasticsearch/info",
        f"/deployments/{deployment_id}/elasticsearch/main-elasticsearch",
        f"/deployments/{deployment_id}",
    ]
    hdrs = {
        'Authorization': f'ApiKey {cloud_api_key}',
        'Content-Type': 'application/json',
    }
    for path in candidate_paths:
        try:
            resp = requests.get(CLOUD_API_BASE + path, headers=hdrs, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                es_resources = data.get('resources', {}).get('elasticsearch', [])
                if es_resources:
                    metadata = es_resources[0].get('info', {}).get('metadata', {})
                    url = metadata.get('aliased_url') or metadata.get('service_url')
                    if url:
                        print(f"Discovered ES endpoint: {url}")
                        return url.rstrip('/')
                metadata = data.get('metadata', {})
                url = metadata.get('aliased_url') or metadata.get('service_url')
                if url:
                    print(f"Discovered ES endpoint: {url}")
                    return url.rstrip('/')
        except Exception as e:
            print(f"Probe failed for {path}: {e}")
            continue
    raise RuntimeError(f"Could not discover ES endpoint for deployment {deployment_id}")

# Parse command-line arguments
def parse_args():
    parser = argparse.ArgumentParser(description="Bulk software/threat inventory to Elasticsearch.")
    parser.add_argument('--credentials', type=str, default=CREDENTIALS_FILE, help='CSV file with username/password')
    return parser.parse_args()

args = parse_args()
CREDENTIALS_FILE = args.credentials
username, password = get_credentials(CREDENTIALS_FILE)
ENDPOINT = discover_es_endpoint(discover_deployment_id(CLOUD_API_KEY), CLOUD_API_KEY)

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
