import os

import requests
from dotenv import load_dotenv

load_dotenv(override=True)

VULNERS_API_URL = "https://vulners.com/api/v3/search/lucene/"


def search_vulnerabilities(query):
    """
    Search vulnerabilities from Vulners API using POST + X-Api-Key header.
    Returns a list of dictionaries with:
    id, title, cvss, href
    """
    api_key = os.getenv("VULNERS_API_KEY", "").strip()

    if not api_key:
        print("Vulners API error: VULNERS_API_KEY not found in environment")
        return []

    headers = {
        "X-Api-Key": api_key,
        "Content-Type": "application/json",
    }

    payload = {
        "query": query,
        "skip": 0,
        "size": 10,
        "fields": ["id", "title", "cvss", "href"],
    }

    try:
        response = requests.post(
            VULNERS_API_URL,
            headers=headers,
            json=payload,
            timeout=15,
        )
        response.raise_for_status()

        data = response.json()
        vulns = []

        if data.get("result") == "OK":
            for item in data.get("data", {}).get("search", []):
                source = item.get("_source", {})

                cvss_data = source.get("cvss")
                if isinstance(cvss_data, dict):
                    cvss_score = cvss_data.get("score")
                else:
                    cvss_score = cvss_data

                vulns.append(
                    {
                        "id": source.get("id") or item.get("id"),
                        "title": source.get("title") or item.get("title"),
                        "cvss": cvss_score,
                        "href": source.get("href") or item.get("href"),
                    }
                )

        print(f"Vulners query worked. Results found: {len(vulns)}")
        return vulns

    except Exception as e:
        print("Vulners API error:", e)
        return []
