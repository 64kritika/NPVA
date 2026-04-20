from unittest.mock import patch, Mock
from npva_core.vuln.vulners_client import search_vulnerabilities

mock_response = {
    "result": "OK",
    "data": {
        "search": [
            {
                "_source": {
                    "id": "CVE-2024-0001",
                    "title": "Sample Apache Vulnerability",
                    "cvss": {"score": 8.1},
                    "href": "https://example.com/CVE-2024-0001"
                }
            },
            {
                "_source": {
                    "id": "CVE-2024-0002",
                    "title": "Sample HTTP Server Issue",
                    "cvss": {"score": 6.5},
                    "href": "https://example.com/CVE-2024-0002"
                }
            }
        ]
    }
}

fake_post = Mock()
fake_post.return_value.json.return_value = mock_response
fake_post.return_value.raise_for_status.return_value = None

with patch("npva_core.vuln.vulners_client.requests.post", fake_post):
    query = 'type:cve AND cpe:"cpe:/a:apache:http_server:2.4.7"'
    results = search_vulnerabilities(query)
    print(results)
    print("Total results:", len(results))
