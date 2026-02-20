#!/usr/bin/env bash
# setup_kibana.sh — Create data views and the Indicator Match detection rule via Kibana API
#
# Usage (fully automatic — reads .env for ELASTIC_CLOUD_API_KEY + credentials CSV):
#   bash setup_kibana.sh
#
# All values are auto-discovered. Override any explicitly if needed:
#   KIBANA_URL=https://<host> KIBANA_USER=elastic KIBANA_PASSWORD=<pw> bash setup_kibana.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ---------- load .env if present ----------
if [ -f "${SCRIPT_DIR}/.env" ]; then
  # shellcheck disable=SC2046
  export $(grep -v '^#' "${SCRIPT_DIR}/.env" | xargs) 2>/dev/null || true
fi

# ---------- discover credentials from CSV if not set ----------
if [ -z "${KIBANA_PASSWORD:-}" ]; then
  echo "==> KIBANA_PASSWORD not set — discovering from credentials CSV..."
  CREDS=$(python3 - <<PYEOF
import csv, os, sys

script_dir = "${SCRIPT_DIR}"
for fname in sorted(os.listdir(script_dir)):
    if not fname.endswith(".csv"):
        continue
    fpath = os.path.join(script_dir, fname)
    try:
        with open(fpath, newline="") as f:
            header = f.readline().lower()
            if "username" not in header or "password" not in header:
                continue
            f.seek(0)
            row = next(csv.DictReader(f))
            print(f"[credentials from: {fname}]", file=sys.stderr)
            print(row["username"])
            print(row["password"])
            sys.exit(0)
    except Exception:
        continue
sys.exit("No credentials CSV found in script directory")
PYEOF
)
  KIBANA_USER=$(echo "${CREDS}" | sed -n '1p')
  KIBANA_PASSWORD=$(echo "${CREDS}" | sed -n '2p')
fi

# ---------- required vars ----------
KIBANA_USER="${KIBANA_USER:-elastic}"
KIBANA_PASSWORD="${KIBANA_PASSWORD:?Could not determine KIBANA_PASSWORD}"

# ---------- discover Kibana URL from Cloud API (credential-matched) if not set ----------
if [ -z "${KIBANA_URL:-}" ]; then
  CLOUD_API_KEY="${ELASTIC_CLOUD_API_KEY:?KIBANA_URL not set and ELASTIC_CLOUD_API_KEY not found. Add it to .env or set KIBANA_URL manually.}"
  echo "==> KIBANA_URL not set — discovering from Elastic Cloud API (testing credentials)..."
  KIBANA_URL=$(python3 - <<PYEOF
import requests, sys

CLOUD_API_BASE = "https://api.elastic-cloud.com/api/v1"
CLOUD_API_KEY  = "${CLOUD_API_KEY}"
USERNAME       = "${KIBANA_USER}"
PASSWORD       = "${KIBANA_PASSWORD}"

hdrs = {"Authorization": f"ApiKey {CLOUD_API_KEY}", "Content-Type": "application/json"}

resp = requests.get(CLOUD_API_BASE + "/deployments", headers=hdrs, timeout=10)
resp.raise_for_status()
deployments = resp.json().get("deployments", [])
if not deployments:
    sys.exit("No deployments found for this Cloud API key")

print(f"Found {len(deployments)} deployment(s): {[d.get('name', d['id']) for d in deployments]}", file=sys.stderr)

for dep in deployments:
    dep_id   = dep["id"]
    dep_name = dep.get("name", dep_id)
    r2 = requests.get(CLOUD_API_BASE + f"/deployments/{dep_id}", headers=hdrs, timeout=10)
    resources = r2.json().get("resources", {})
    kb_resources = resources.get("kibana", [])
    es_resources = resources.get("elasticsearch", [])
    if not kb_resources or not es_resources:
        continue
    kb_meta = kb_resources[0].get("info", {}).get("metadata", {})
    es_meta = es_resources[0].get("info", {}).get("metadata", {})
    kb_url = kb_meta.get("aliased_url") or kb_meta.get("service_url")
    es_url = es_meta.get("aliased_url") or es_meta.get("service_url")
    if not kb_url or not es_url:
        continue
    # Test credentials against the ES endpoint (reliable auth check)
    try:
        test = requests.get(es_url.rstrip("/"), auth=(USERNAME, PASSWORD), timeout=10)
        if test.status_code == 200:
            print(f"[matched deployment: {dep_name}]", file=sys.stderr)
            print(kb_url.rstrip("/"))
            sys.exit(0)
    except Exception:
        continue

# Fall back to first deployment with a Kibana resource
for dep in deployments:
    dep_id   = dep["id"]
    dep_name = dep.get("name", dep_id)
    r2 = requests.get(CLOUD_API_BASE + f"/deployments/{dep_id}", headers=hdrs, timeout=10)
    kb_resources = r2.json().get("resources", {}).get("kibana", [])
    if not kb_resources:
        continue
    metadata = kb_resources[0].get("info", {}).get("metadata", {})
    url = metadata.get("aliased_url") or metadata.get("service_url")
    if url:
        print(f"[no ES credential match, falling back to: {dep_name}]", file=sys.stderr)
        print(url.rstrip("/"))
        sys.exit(0)

sys.exit("Could not find a Kibana URL in any deployment")
PYEOF
)
fi

AUTH="${KIBANA_USER}:${KIBANA_PASSWORD}"
HEADERS=(-H "kbn-xsrf: true" -H "Content-Type: application/json")

echo "==> Kibana: ${KIBANA_URL}"

# ---------- helper ----------
kibana_post() {
  local path="$1"
  local body="$2"
  local desc="$3"
  echo -n "  ${desc} ... "
  status=$(curl -s -o /tmp/kb_resp.json -w "%{http_code}" \
    -u "${AUTH}" "${HEADERS[@]}" \
    -X POST "${KIBANA_URL}${path}" \
    -d "${body}")
  if [[ "${status}" =~ ^2 ]]; then
    echo "OK (${status})"
  else
    echo "WARN (${status})"
    cat /tmp/kb_resp.json
    echo
  fi
}

# ---------- 1. Data views ----------
echo
echo "==> Creating data views..."

kibana_post "/api/content_management/rpc/create" '{
  "contentTypeId": "index-pattern",
  "data": {
    "fieldAttrs": "{}",
    "title": "software",
    "timeFieldName": "@timestamp",
    "sourceFilters": "[]",
    "fields": "[]",
    "fieldFormatMap": "{}",
    "runtimeFieldMap": "{}",
    "name": "software",
    "allowHidden": false
  },
  "options": { "id": "software", "overwrite": true },
  "version": 1
}' "data view: software"

kibana_post "/api/content_management/rpc/create" '{
  "contentTypeId": "index-pattern",
  "data": {
    "fieldAttrs": "{}",
    "title": "eol-versions",
    "timeFieldName": "@timestamp",
    "sourceFilters": "[]",
    "fields": "[]",
    "fieldFormatMap": "{}",
    "runtimeFieldMap": "{}",
    "name": "eol-versions",
    "allowHidden": false
  },
  "options": { "id": "eol-versions", "overwrite": true },
  "version": 1
}' "data view: eol-versions"

# ---------- 2. Detection rule ----------
echo
echo "==> Creating Indicator Match detection rule..."

kibana_post "/api/detection_engine/rules" '{
  "rule_id": "indicator-match-repro",
  "name": "Indicator Match Repro — EOL Software",
  "description": "Reproduces false positives in indicator match with AND conditions (kibana#179825)",
  "risk_score": 21,
  "severity": "low",
  "interval": "1m",
  "from": "now-120s",
  "type": "threat_match",
  "language": "kuery",
  "index": ["software"],
  "query": "*:*",
  "enabled": true,
  "filters": [],
  "threat_query": "@timestamp >= \"now-30d/d\"",
  "threat_index": ["eol-versions"],
  "threat_mapping": [
    {
      "entries": [
        {
          "field": "version.keyword",
          "type": "mapping",
          "value": "threat.indicator.version.keyword"
        },
        {
          "field": "software.keyword",
          "type": "mapping",
          "value": "threat.indicator.software.keyword"
        }
      ]
    }
  ],
  "threat_language": "kuery",
  "threat_indicator_path": "threat.indicator"
}' "detection rule: indicator-match-repro"

echo
echo "Done. Open Security → Rules in Kibana to verify."
