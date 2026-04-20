from .vulners_client import search_vulnerabilities


def clean_version(version):
    """
    Keep only the main version token.
    Example:
    '6.6.1p1 Ubuntu 2ubuntu2.13' -> '6.6.1p1'
    """
    if not version:
        return None

    version = str(version).strip()
    if not version:
        return None

    return version.split()[0]


def normalize(text):
    """
    Normalize text for safer matching.
    """
    return (text or "").strip().lower()


def build_best_query(service):
    """
    Build the best possible Vulners search query
    using CPE, product, version, and service name.
    """
    cpe = (service.get("cpe") or "").strip()
    product = (service.get("product") or "").strip()
    service_name = (service.get("service") or "").strip()
    version = clean_version(service.get("version"))

    if cpe:
        return f'type:cve AND cpe:"{cpe}"'

    if product and version:
        return f'type:cve AND "{product}" AND "{version}"'

    if service_name and version:
        return f'type:cve AND "{service_name}" AND "{version}"'

    if product:
        return f'type:cve AND "{product}"'

    if service_name:
        return f'type:cve AND "{service_name}"'

    return None


def add_severity(vulnerabilities):
    """
    Add High / Medium / Low / Unknown severity based on CVSS.
    """
    results = []

    for vuln in vulnerabilities:
        try:
            score = float(vuln.get("cvss")) if vuln.get("cvss") is not None else 0.0
        except Exception:
            score = 0.0

        if score >= 7.0:
            severity = "High"
        elif score >= 4.0:
            severity = "Medium"
        elif score > 0:
            severity = "Low"
        else:
            severity = "Unknown"

        item = dict(vuln)
        item["severity"] = severity
        results.append(item)

    return results


def fallback_known_vulns(service):
    """
    Fallback CVEs for well-known vulnerable services commonly found in Metasploitable.
    This does not change the workflow. It only prevents empty results when a known
    vulnerable version is detected but Vulners returns nothing.
    """
    product = normalize(service.get("product"))
    service_name = normalize(service.get("service"))
    version = clean_version(service.get("version"))
    version = normalize(version)

    known = []

    if (product == "vsftpd" or service_name == "ftp") and version == "2.3.4":
        known.append({
            "id": "CVE-2011-2523",
            "title": "vsftpd 2.3.4 backdoor vulnerability",
            "cvss": 10.0,
            "description": "Known backdoor vulnerability in vsftpd 2.3.4"
        })

    if (product == "unrealircd" or "irc" in service_name) and version == "3.2.8.1":
        known.append({
            "id": "CVE-2010-2075",
            "title": "UnrealIRCd backdoor vulnerability",
            "cvss": 10.0,
            "description": "Known backdoor vulnerability in UnrealIRCd 3.2.8.1"
        })

    if product == "distccd" and version == "1.1":
        known.append({
            "id": "CVE-2004-2687",
            "title": "distccd remote command execution vulnerability",
            "cvss": 9.8,
            "description": "Known remote command execution vulnerability in distccd 1.1"
        })

    if product == "samba" and version.startswith("3.0.20"):
        known.append({
            "id": "CVE-2007-2447",
            "title": "Samba username map script command execution vulnerability",
            "cvss": 10.0,
            "description": "Known command execution vulnerability in Samba 3.0.20"
        })

    return add_severity(known)


def map_service_to_cves(service):
    """
    Get vulnerabilities for one detected service.
    First try Vulners. If nothing is returned, use fallback known vulnerable services.
    """
    query = build_best_query(service)

    if not query:
        print("DEBUG: No query could be built, trying fallback.")
        return fallback_known_vulns(service)

    print("DEBUG QUERY:", query)

    vulnerabilities = search_vulnerabilities(query)

    print("DEBUG VULNS FOUND:", len(vulnerabilities))

    if vulnerabilities:
        return add_severity(vulnerabilities)

    print("DEBUG FALLBACK USED FOR:", service)
    return fallback_known_vulns(service)
