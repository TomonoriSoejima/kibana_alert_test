# Reproducing Indicator Match Rule False Positives in Elastic Security

## Purpose
This project demonstrates how the Indicator Match rule in Elastic Security can produce false positive alerts when using AND conditions, as described in [elastic/kibana#179825](https://github.com/elastic/kibana/issues/179825).

## What This Project Does
- Simulates a software inventory (`software` index) and a list of end-of-life (EOL) software versions (`eol-versions` index).
- Uses `bulk_software_inventory.py` to:
  - Send all EOL indicator documents (for `eol-versions`) once at startup (bootstrapping).
  - Continuously send software inventory documents (for `software`) in a loop.
- Allows you to set up and test Indicator Match rules in Elastic Security.

## Steps to Reproduce
1. **Run `bulk_software_inventory.py`** to populate the `eol-versions` index (once) and continuously populate the `software` index.
2. **Create two data views** in Kibana:
   - `software`
   - `eol-versions`
3. **Set up an Indicator Match rule** in Elastic Security that matches on fields like `software`/`threat.indicator.software` and `version`/`threat.indicator.version` using AND conditions.
4. **Observe the alerts** generated. You may see false positives due to the way AND logic is applied in the rule engine, as described in the linked issue.

## Why This Matters
This setup helps you:
- Understand and reproduce a known issue with Indicator Match rules and AND conditions in Elastic Security.
- Test your own rules and mappings to see if you are affected by this false positive scenario.
- Provide feedback or additional details to Elastic if you encounter the same or related issues.

## Usage
- To run the script and send data:
  ```bash
  python3 bulk_software_inventory.py --endpoint <your-endpoint> --credentials <your-credentials-csv>
  ```

## Creating the Indicator Match Rule in Kibana

To create the Indicator Match rule in Kibana:

1. Open **Kibana → Dev Tools**.
2. Paste the following into the console:

```
POST kbn:api/detection_engine/rules
{
  "rule_id": "new-rule",
  "name": "my-new-rule",
  "description": "indicator match test",
  "risk_score": 21,
  "severity": "low",
  "interval": "1m",
  "from": "now-120s",
  "type": "threat_match",
  "language": "kuery",
  "index": [
    "software"
  ],
  "query": "*:*",
  "enabled": true,
  "filters": [],
  "threat_query": "@timestamp >= \"now-30d/d\"",
  "threat_index": [
    "eol-versions"
  ],
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
}
```

3. Click the **Play** (▶️) button to execute and create the rule.

This will set up the Indicator Match rule as described in the [GitHub issue](https://github.com/elastic/kibana/issues/179825) and allow you to observe the matching and potential false positives.

## References
- [Elastic Security Indicator Match Rule Documentation](https://www.elastic.co/guide/en/security/current/indicator-match-rule.html)
- [GitHub Issue: Indicator Match rule can produce false positive alerts if you use AND conditions](https://github.com/elastic/kibana/issues/179825)

---

**Note:**
- You must manually create the data views (`software` and `eol-versions`) in Kibana after running the scripts.
- The script now handles EOL indicator bootstrapping automatically; you do not need a separate script for EOL data.
- Adjust the scripts or data as needed to match your environment or test case.
