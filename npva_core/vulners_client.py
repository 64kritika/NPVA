# npva_core/vuln/vulners_client.py
import os
import requests
from typing import Dict, List, Optional, Any

VULNERS_URL = "https://vulners.com/api/v3/search/lucene/"


def build_query_from_service(service: Dict[str, Any]) -> Optional[str]:
    """
    Build a Vulners Lucene query from an nmap service dict.
    service example keys: product, version, cpe, service, port, state...
    """
    cpe = (service.get("cpe") or "").strip()
    product = (service.get("product") or "").strip()
    version = (service.get("version") or "").strip()

    # Best: use CPE if available
    if cpe:
        # Vulners lucene often supports cpe field searches
        return f'cpe:"{cpe}"'

    # Fallback: product + version text search
    if product and version:
        return f'"{product}" "{version}"'

    # Fallback: product only
    if product:
        return f'"{product}"'

    return None


def search_vulnerabilities(query: str, size: int = 10) -> List[Dict[str, Any]]:
    """
    Query Vulners and return a list of vulnerabilities.
    Each item: {id, title, cvss, link}
    """
    api_key = os.getenv("VULNERS_API_KEY")
    if not api_key:
        raise ValueError("VULNERS_API_KEY not found. Put it in your .env file.")

    payload = {"query": query, "size": size, "apiKey": api_key}

    try:
        r = requests.post(VULNERS_URL, json=payload, timeout=20)
        r.raise_for_status()
        j = r.json()
    except Exception:
        return []

    if j.get("result") != "OK":
        return []

    vulns: List[Dict[str, Any]] = []
    for item in j.get("data", {}).get("search", []) or []:
        # Vulners sometimes returns different shapes; keep it robust
        vid = item.get("id") or item.get("_id") or ""
        title = item.get("title") or item.get("_source", {}).get("title") or vid
        href = item.get("href") or item.get("_source", {}).get("href") or ""

        cvss_score = None
        cvss_obj = item.get("cvss") or item.get("_source", {}).get("cvss") or {}
        if isinstance(cvss_obj, dict):
            cvss_score = cvss_obj.get("score")

        vulns.append(
            {"id": vid, "title": title, "cvss": cvss_score, "link": href}
        )

    return vulns