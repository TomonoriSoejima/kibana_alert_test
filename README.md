# Indicator Match Rule False Positives — Repro

Reproduces false positive alerts from Indicator Match rules using AND conditions.
See [elastic/kibana#179825](https://github.com/elastic/kibana/issues/179825).

## How it works

- `bulk_software_inventory.py` populates two indexes:
  - `eol-versions` — threat indicator documents (bootstrapped once at startup)
  - `software` — software inventory documents (sent in a loop every 30 seconds)
- The script auto-discovers the Elasticsearch endpoint and credentials from `.env` and a local CSV file.

## Quick Start

**1. Add your Cloud API key to `.env`:**
```
ELASTIC_CLOUD_API_KEY=<your-key>
```

**2. Place a credentials CSV** (with `username` and `password` columns) in the same directory.

**3. Send data to Elasticsearch:**
```bash
python3 bulk_software_inventory.py
```

**4. Run Kibana setup** (data views + detection rule):
```bash
bash setup_kibana.sh
```
Kibana URL and credentials are auto-discovered from the Cloud API key (`.env`) and the credentials CSV. Override any value explicitly if needed.

## References
- [Indicator Match Rule docs](https://www.elastic.co/guide/en/security/current/indicator-match-rule.html)
- [GitHub Issue #179825](https://github.com/elastic/kibana/issues/179825)
