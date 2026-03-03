from flask import Flask, render_template, request
from npva_core.scanner.nmap_runner import run_nmap_xml
from npva_core.scanner.nmap_parser import parse_nmap_xml
from npva_core.db.repo import (
    init_db,
    create_scan,
    finish_scan,
    insert_host,
    insert_service,
    list_scans,
    get_scan_details,
)

app = Flask(__name__)

# Initialize DB tables on startup
init_db()

@app.route("/")
def index():
    return render_template("index.html")

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

        # Save to DB
        for h in data["hosts"]:
            host_id = insert_host(scan_id, h["ip"], h["status"])
            for svc in h["ports"]:
                insert_service(host_id, svc)

        finish_scan(scan_id, "completed")
        scan_row = {"id": scan_id, "target": target, "status": "completed"}

        return render_template("results.html", data=data, scan=scan_row)

    except Exception as e:
        finish_scan(scan_id, "failed")
        return f"Scan failed: {e}", 500

@app.route("/scan/<int:scan_id>")
def scan_view(scan_id: int):
    details = get_scan_details(scan_id)
    # details = {"scan": {...}, "hosts": [...]}
    data = {"hosts": details["hosts"]}
    return render_template("results.html", data=data, scan=details["scan"])

if __name__ == "__main__":
    app.run(debug=True)
