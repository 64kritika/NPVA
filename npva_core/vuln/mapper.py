from .vulners_client import search_vulnerabilities


def map_service_to_cves(service):
    """
    Build best possible query from Nmap service data
    and fetch vulnerabilities from Vulners.
    """

    cpe = service.get("cpe")
    product = service.get("product")
    version = service.get("version")
    name = service.get("service")

    query = None

    # 1️⃣ Best: use CPE
    if cpe:
        query = cpe

    # 2️⃣ product + version
    elif product and version:
        query = f"{product} {version}"

    # 3️⃣ service + version
    elif name and version:
        query = f"{name} {version}"

    # 4️⃣ fallback service name
    elif name:
        query = name

    if not query:
        return []

    vulns = search_vulnerabilities(query)

    return vulns