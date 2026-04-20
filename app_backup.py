import csv
import io
import os

from dotenv import load_dotenv
from flask import Flask, Response, render_template, request

from npva_core.scanner.nmap_runner import run_nmap_xml
from npva_core.scanner.nmap_parser import parse_nmap_xml
from npva_core.vuln.mapper import map_service_to_cves
from npva_core.db.repo import (
    init_db,
    create_scan,
    finish_scan,
    insert_host,
    insert_service,
    insert_vulnerability,
    list_scans,
    get_scan_details,
)
from npva_core.monitoring.wazuh_reader import get_recent_alerts

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"), override=True)

app = Flask(__name__)

# Initialize DB tables on startup
init_db()


def compute_totals_and_attach_vulns(data):
    """
    Attach vulnerabilities to each port/service entry and compute totals.
    """
    totals = {"open_ports": 0, "vulns": 0, "high_risk": 0}

    for host in data.get("hosts", []):
        for port in host.get("ports", []):
            if (port.get("state") or "").lower() == "open":
                totals["open_ports"] += 1

            # Only fetch live if vulns are not already present
            if "vulns" not in port:
                vulns = map_service_to_cves(port)
                port["vulns"] = vulns
            else:
                vulns = port.get("vulns", [])

            totals["vulns"] += len(vulns)

            for vuln in vulns:
                try:
                    score = float(vuln.get("cvss")) if vuln.get("cvss") is not None else 0.0
                except Exception:
                    score = 0.0

                if score >= 7.0:
                    totals["high_risk"] += 1

    return totals


def load_wazuh_alerts(limit=5, agent_name=None):
    """
    Fetch recent Wazuh alerts safely.
    Keeps app running even if Wazuh fails.
    """
    try:
        alerts = get_recent_alerts(limit=limit, agent_name=agent_name)
        print("WAZUH ALERTS RETURNED:", alerts)
        return alerts
    except Exception as e:
        print("Wazuh alert fetch error:", e)
        return []


@app.route("/")
def index():
    alerts = load_wazuh_alerts(limit=5, agent_name=None)
    return render_template(
        "index.html",
        totals={"open_ports": 0, "vulns": 0, "high_risk": 0},
        alerts=alerts,
    )


@app.route("/history")
def history():
    scans = list_scans(limit=50)
    alerts = load_wazuh_alerts(limit=5, agent_name=None)
    return render_template("history.html", scans=scans, alerts=alerts)


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target", "").strip()
    if not target:
        return "Target is required", 400

    scan_id = create_scan(target)

    try:
        xml_out = run_nmap_xml(target)
        data = parse_nmap_xml(xml_out)

        # Fetch live vulnerabilities and compute totals
        totals = compute_totals_and_attach_vulns(data)

        # Save all scan results into DB, including vulnerabilities
        for host in data.get("hosts", []):
            host_id = insert_host(scan_id, host.get("ip"), host.get("status"))

            for port in host.get("ports", []):
                service_id = insert_service(host_id, port)

                for vuln in port.get("vulns", []) or []:
                    insert_vulnerability(service_id, vuln)

        finish_scan(scan_id, "completed")

        scan_row = {
            "id": scan_id,
            "target": target,
            "status": "completed",
        }

        alerts = load_wazuh_alerts(limit=5, agent_name=None)

        return render_template(
            "results.html",
            data=data,
            scan=scan_row,
            totals=totals,
            alerts=alerts,
        )

    except Exception as e:
        finish_scan(scan_id, "failed")
        return f"Scan failed: {e}", 500


@app.route("/scan/<int:scan_id>")
def scan_view(scan_id):
    details = get_scan_details(scan_id)
    data = {"hosts": details.get("hosts", [])}

    totals = compute_totals_and_attach_vulns(data)
    alerts = load_wazuh_alerts(limit=5, agent_name=None)

    return render_template(
        "results.html",
        data=data,
        scan=details.get("scan"),
        totals=totals,
        alerts=alerts,
    )


@app.route("/reports")
def reports():
    scans = list_scans(limit=100)
    alerts = load_wazuh_alerts(limit=5, agent_name=None)
    return render_template("reports.html", scans=scans, alerts=alerts)


@app.route("/report/<int:scan_id>")
def report_view(scan_id):
    details = get_scan_details(scan_id)
    data = {"hosts": details.get("hosts", [])}
    totals = compute_totals_and_attach_vulns(data)
    alerts = load_wazuh_alerts(limit=5, agent_name=None)

    vuln_rows = []
    for host in data.get("hosts", []):
        for port in host.get("ports", []):
            for vuln in port.get("vulns", []) or []:
                vuln_rows.append(
                    {
                        "ip": host.get("ip"),
                        "port": port.get("port"),
                        "proto": port.get("proto"),
                        "service": port.get("service"),
                        "product": port.get("product"),
                        "version": port.get("version"),
                        "cpe": port.get("cpe"),
                        "vuln_id": vuln.get("id"),
                        "cvss": vuln.get("cvss"),
                        "severity": vuln.get("severity"),
                        "title": vuln.get("title"),
                        "href": vuln.get("href"),
                    }
                )

    return render_template(
        "report_view.html",
        scan=details.get("scan"),
        data=data,
        totals=totals,
        vuln_rows=vuln_rows,
        alerts=alerts,
    )


@app.route("/export/ports/<int:scan_id>.csv")
def export_ports_csv(scan_id):
    details = get_scan_details(scan_id)
    hosts = details.get("hosts", [])
    scan = details.get("scan", {})
    target = scan.get("target")

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "scan_id",
            "target",
            "host_ip",
            "port",
            "proto",
            "state",
            "service",
            "product",
            "version",
            "cpe",
        ]
    )

    for host in hosts:
        ip = host.get("ip")
        for port in host.get("ports", []):
            writer.writerow(
                [
                    scan_id,
                    target,
                    ip,
                    port.get("port"),
                    port.get("proto"),
                    port.get("state"),
                    port.get("service"),
                    port.get("product"),
                    port.get("version"),
                    port.get("cpe"),
                ]
            )

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=scan_{scan_id}_ports.csv"
        },
    )


@app.route("/export/vulns/<int:scan_id>.csv")
def export_vulns_csv(scan_id):
    details = get_scan_details(scan_id)
    data = {"hosts": details.get("hosts", [])}
    scan = details.get("scan", {})
    target = scan.get("target")

    compute_totals_and_attach_vulns(data)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "scan_id",
            "target",
            "host_ip",
            "port",
            "proto",
            "service",
            "product",
            "version",
            "vuln_id",
            "cvss",
            "severity",
            "title",
            "href",
        ]
    )

    for host in data.get("hosts", []):
        ip = host.get("ip")
        for port in host.get("ports", []):
            for vuln in port.get("vulns", []) or []:
                writer.writerow(
                    [
                        scan_id,
                        target,
                        ip,
                        port.get("port"),
                        port.get("proto"),
                        port.get("service"),
                        port.get("product"),
                        port.get("version"),
                        vuln.get("id"),
                        vuln.get("cvss"),
                        vuln.get("severity"),
                        vuln.get("title"),
                        vuln.get("href"),
                    ]
                )

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=scan_{scan_id}_vulns.csv"
        },
    )


@app.route("/vulnerabilities")
def vulnerabilities():
    scans = list_scans(limit=100)
    latest_scan = dict(scans[0]) if scans else None
    vuln_rows = []
    alerts = load_wazuh_alerts(limit=5, agent_name=None)

    if latest_scan:
        details = get_scan_details(latest_scan["id"])
        data = {"hosts": details.get("hosts", [])}

        compute_totals_and_attach_vulns(data)

        for host in data.get("hosts", []):
            for port in host.get("ports", []):
                for vuln in port.get("vulns", []) or []:
                    vuln_rows.append(
                        {
                            "scan_id": latest_scan.get("id"),
                            "target": latest_scan.get("target"),
                            "ip": host.get("ip"),
                            "port": port.get("port"),
                            "proto": port.get("proto"),
                            "service": port.get("service"),
                            "product": port.get("product"),
                            "version": port.get("version"),
                            "cpe": port.get("cpe"),
                            "vuln_id": vuln.get("id"),
                            "cvss": vuln.get("cvss"),
                            "severity": vuln.get("severity", "Unknown"),
                            "title": vuln.get("title"),
                            "href": vuln.get("href"),
                        }
                    )

    return render_template(
        "vulnerabilities.html",
        latest_scan=latest_scan,
        vuln_rows=vuln_rows,
        alerts=alerts,
    )


@app.route("/alerts")
def alerts():
    wazuh_alerts = load_wazuh_alerts(limit=20, agent_name=None)
    print("ALERTS PAGE DATA:", wazuh_alerts)
    return render_template("alerts.html", alerts=wazuh_alerts)


if __name__ == "__main__":
    app.run(debug=True)
