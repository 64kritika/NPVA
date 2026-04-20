import requests
import urllib3
from datetime import datetime

urllib3.disable_warnings()

WAZUH_INDEXER_URL = "https://192.168.56.105:9200"
WAZUH_USERNAME = "admin"
WAZUH_PASSWORD = "admin"
WAZUH_INDEX_PATTERN = "wazuh-alerts-*"


def get_recent_alerts(limit=5, agent_name=None):
    url = f"{WAZUH_INDEXER_URL}/{WAZUH_INDEX_PATTERN}/_search"

    query = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": [
            "timestamp",
            "agent.name",
            "rule.id",
            "rule.level",
            "rule.description",
            "location",
            "syscheck.path",
        ],
    }

    if agent_name:
        query["query"] = {
            "bool": {
                "filter": [
                    {"term": {"agent.name.keyword": agent_name}}
                ]
            }
        }

    response = requests.get(
        url,
        auth=(WAZUH_USERNAME, WAZUH_PASSWORD),
        json=query,
        verify=False,
        timeout=2,
    )
    response.raise_for_status()

    data = response.json()
    hits = data.get("hits", {}).get("hits", [])

    alerts = []
    for hit in hits:
        src = hit.get("_source", {})
        agent = src.get("agent", {}) or {}
        rule = src.get("rule", {}) or {}
        syscheck = src.get("syscheck", {}) or {}

        raw_time = src.get("timestamp", "-")
        try:
            dt = datetime.strptime(raw_time, "%Y-%m-%dT%H:%M:%S.%f%z")
            formatted_time = dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            formatted_time = raw_time

        alerts.append({
            "time": formatted_time,
            "agent": agent.get("name", "-"),
            "rule_id": rule.get("id", "-"),
            "level": rule.get("level", "-"),
            "description": rule.get("description", "-"),
            "location": src.get("location", "-"),
            "path": syscheck.get("path", "-"),
        })

    return alerts
