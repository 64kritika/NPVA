from __future__ import annotations
import xml.etree.ElementTree as ET
from typing import Any, Dict

def parse_nmap_xml(xml_text: str) -> Dict[str, Any]:
    root = ET.fromstring(xml_text)
    result: Dict[str, Any] = {"hosts": []}

    for host in root.findall("host"):
        status_el = host.find("status")
        status = status_el.get("state") if status_el is not None else "unknown"

        addr_el = host.find("address[@addrtype='ipv4']")
        ip = addr_el.get("addr") if addr_el is not None else "unknown"

        host_obj: Dict[str, Any] = {"ip": ip, "status": status, "ports": []}

        ports_el = host.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                proto = port_el.get("protocol", "unknown")
                portid = port_el.get("portid", "0")
                state_el = port_el.find("state")
                state = state_el.get("state") if state_el is not None else "unknown"

                svc_el = port_el.find("service")
                service = svc_el.get("name") if svc_el is not None else ""
                product = svc_el.get("product") if svc_el is not None else ""
                version = svc_el.get("version") if svc_el is not None else ""

                # Try to read the first CPE entry if present
                cpe = ""
                if svc_el is not None:
                    cpe_el = svc_el.find("cpe")
                    if cpe_el is not None and cpe_el.text:
                        cpe = cpe_el.text.strip()

                host_obj["ports"].append(
                    {
                        "port": int(portid),
                        "proto": proto,
                        "state": state,
                        "service": service,
                        "product": product,
                        "version": version,
                        "cpe": cpe,
                    }
                )

        result["hosts"].append(host_obj)

    return result
