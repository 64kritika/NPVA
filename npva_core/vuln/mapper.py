from .vulners_client import search_vulnerabilities

def map_service_to_cves(service_name, version=None):
    """
    Map a service name and version to CVEs using Vulners API
    """
    if not service_name:
        return []

    query = service_name

    if version:
        query += f" {version}"

    vulnerabilities = search_vulnerabilities(query)

    return vulnerabilities