import requests
import os

VULNERS_API_URL = "https://vulners.com/api/v3/search/lucene/"


def search_vulnerabilities(query):
    """
    Search vulnerabilities from Vulners API using service name and version
    """
    
    api_key = os.getenv("VULNERS_API_KEY")

    params = {
        "query": query,
        "size": 10
    }

    if api_key:
        params["apiKey"] = api_key

    try:
        response = requests.get(VULNERS_API_URL, params=params, timeout=10)
        data = response.json()

        vulns = []

        if data.get("result") == "OK":
            for item in data["data"]["search"]:
                source = item["_source"]

                vulns.append({
                    "id": source.get("id"),
                    "title": source.get("title"),
                    "cvss": source.get("cvss", {}).get("score"),
                    "href": source.get("href")
                })

        return vulns

    except Exception as e:
        print("Vulners API error:", e)
        return []