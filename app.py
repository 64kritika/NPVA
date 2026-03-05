# app.py
from dotenv import load_dotenv
from flask import Flask, render_template, request

from npva_core.scanner.nmap_runner import run_nmap_xml
from npva_core.scanner.nmap_parser import parse_nmap_xml

# ✅ Use mapper only (do NOT import build_query_from_service / search_vulnerabilities here)
from npva_core.vuln.mapper import map_service_to_cves

from npva_core.db.repo import (
    init_db,
    create_scan,
    finish_scan,
    insert_host,
    insert_service,
    list_scans,
    get_scan_details,
)

load_dotenv()

app = Flask(__name__)

# Initialize DB tables on startup
init_db()


def compute_totals_and_attach_vulns(data):
    """
    Adds 'vulns' list to each port/service dict in:
      data['hosts'][...]['ports'][...]
    Returns totals dict for dashboard cards.
    """
    totals = {"open_ports": 0, "vulns": 0, "high_risk": 0}

    for host in data.get("hosts", []):
        for port in host.get("ports", []):
            # 1) open ports count
            if (port.get("state") or "").lower() == "open":
                totals["open_ports"] += 1

            # 2) determine service + version (based on your nmap_parser keys)
            service_name = (port.get("service") or "").strip()
            version = (port.get("version") or "").strip() or None

            # Sometimes nmap provides product separately; use it if version empty
            if not version:
                version = (port.get("product") or "").strip() or None

            # 3) Vulners lookup
            vulns = map_service_to_cves(service_name, version)
            port["vulns"] = vulns

            totals["vulns"] += len(vulns)

            # 4) high risk = CVSS >= 7.0
            for v in vulns:
                try:
                    score = float(v.get("cvss")) if v.get("cvss") is not None else 0.0
                except Exception:
                    score = 0.0
                if score >= 7.0:
                    totals["high_risk"] += 1

    return totals


@app.route("/")
def index():
    return render_template(
        "index.html",
        totals={"open_ports": 0, "vulns": 0, "high_risk": 0},
    )


@app.route("/history")
def history():
    scans = list_scans(limit=50)
    return render_template("history.html", scans=scans)


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target", "").strip()
    if not target:
        return "Target is required", 400

    scan_id = create_scan(target)

    try:
        xml_out = run_nmap_xml(target)
        data = parse_nmap_xml(xml_out)

        # Attach vulns + compute totals
        totals = compute_totals_and_attach_vulns(data)

        # Save to DB
        for h in data.get("hosts", []):
            host_id = insert_host(scan_id, h.get("ip"), h.get("status"))
            for p in h.get("ports", []):
                insert_service(host_id, p)

        finish_scan(scan_id, "completed")
        scan_row = {"id": scan_id, "target": target, "status": "completed"}

        return render_template("results.html", data=data, scan=scan_row, totals=totals)

    except Exception as e:
        finish_scan(scan_id, "failed")
        return f"Scan failed: {e}", 500


@app.route("/scan/<int:scan_id>")
def scan_view(scan_id: int):
    details = get_scan_details(scan_id)

    # Expecting details["hosts"] with each host containing "ports" list
    data = {"hosts": details.get("hosts", [])}

    # Recompute vulns for stored services so history shows vulns too
    totals = compute_totals_and_attach_vulns(data)

    return render_template(
        "results.html",
        data=data,
        scan=details.get("scan"),
        totals=totals,
    )


if __name__ == "__main__":
    app.run(debug=True)