import os
import sqlite3
from datetime import datetime
from typing import Any, Dict, List

DB_PATH = os.path.join("instance", "npva.sqlite3")

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL,
  ip TEXT NOT NULL,
  status TEXT NOT NULL,
  FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS services (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id INTEGER NOT NULL,
  port INTEGER NOT NULL,
  proto TEXT NOT NULL,
  state TEXT NOT NULL,
  service TEXT,
  product TEXT,
  version TEXT,
  cpe TEXT,
  FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  service_id INTEGER NOT NULL,
  vuln_id TEXT NOT NULL,
  title TEXT,
  cvss REAL,
  severity TEXT,
  href TEXT,
  FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
);

-- ✅ NEW TABLE (WAZUH ALERTS)
CREATE TABLE IF NOT EXISTS wazuh_alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  alert_time TEXT,
  agent_name TEXT,
  rule_id TEXT,
  rule_level INTEGER,
  description TEXT,
  location TEXT,
  path TEXT,
  UNIQUE(alert_time, agent_name, rule_id, description)
);
"""


def _connect() -> sqlite3.Connection:
    os.makedirs("instance", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = _connect()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def create_scan(target: str) -> int:
    conn = _connect()
    try:
        started = datetime.utcnow().isoformat()
        cur = conn.execute(
            "INSERT INTO scans(target, started_at, status) VALUES (?, ?, ?)",
            (target, started, "running"),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def finish_scan(scan_id: int, status: str) -> None:
    conn = _connect()
    try:
        finished = datetime.utcnow().isoformat()
        conn.execute(
            "UPDATE scans SET finished_at=?, status=? WHERE id=?",
            (finished, status, scan_id),
        )
        conn.commit()
    finally:
        conn.close()


def create_host(scan_id: int, ip: str, status: str) -> int:
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT INTO hosts(scan_id, ip, status) VALUES (?, ?, ?)",
            (scan_id, ip, status),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def insert_host(scan_id: int, ip: str, status: str) -> int:
    return create_host(scan_id, ip, status)


def create_service(host_id: int, svc: Dict[str, Any]) -> int:
    conn = _connect()
    try:
        cur = conn.execute(
            """
            INSERT INTO services(host_id, port, proto, state, service, product, version, cpe)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                host_id,
                int(svc.get("port", 0)),
                svc.get("proto", ""),
                svc.get("state", ""),
                svc.get("service", ""),
                svc.get("product", ""),
                svc.get("version", ""),
                svc.get("cpe", ""),
            ),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def insert_service(host_id: int, svc: Dict[str, Any]) -> int:
    return create_service(host_id, svc)


def _severity_from_cvss(cvss: Any) -> str:
    try:
        score = float(cvss) if cvss is not None else 0.0
    except Exception:
        score = 0.0

    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Unknown"


def insert_vulnerability(service_id: int, vuln: Dict[str, Any]) -> int:
    conn = _connect()
    try:
        severity = vuln.get("severity") or _severity_from_cvss(vuln.get("cvss"))
        cur = conn.execute(
            """
            INSERT INTO vulnerabilities(service_id, vuln_id, title, cvss, severity, href)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                service_id,
                vuln.get("id", ""),
                vuln.get("title", ""),
                vuln.get("cvss"),
                severity,
                vuln.get("href", ""),
            ),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def clear_service_vulnerabilities(service_id: int) -> None:
    conn = _connect()
    try:
        conn.execute("DELETE FROM vulnerabilities WHERE service_id=?", (service_id,))
        conn.commit()
    finally:
        conn.close()


def list_scans(limit: int = 20) -> List[sqlite3.Row]:
    conn = _connect()
    try:
        cur = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return cur.fetchall()
    finally:
        conn.close()


def get_scan_details(scan_id: int) -> Dict[str, Any]:
    conn = _connect()
    try:
        scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not scan:
            raise KeyError("Scan not found")

        hosts = conn.execute(
            "SELECT * FROM hosts WHERE scan_id=? ORDER BY id ASC",
            (scan_id,),
        ).fetchall()

        host_objs: List[Dict[str, Any]] = []

        for host in hosts:
            services = conn.execute(
                "SELECT * FROM services WHERE host_id=? ORDER BY port ASC",
                (host["id"],),
            ).fetchall()

            port_objs: List[Dict[str, Any]] = []

            for service in services:
                vulns = conn.execute(
                    """
                    SELECT vuln_id, title, cvss, severity, href
                    FROM vulnerabilities
                    WHERE service_id=?
                    ORDER BY
                      CASE severity
                        WHEN 'High' THEN 1
                        WHEN 'Medium' THEN 2
                        WHEN 'Low' THEN 3
                        ELSE 4
                      END,
                      cvss DESC
                    """,
                    (service["id"],),
                ).fetchall()

                port_data = dict(service)
                port_data["vulns"] = [
                    {
                        "id": v["vuln_id"],
                        "title": v["title"],
                        "cvss": v["cvss"],
                        "severity": v["severity"],
                        "href": v["href"],
                    }
                    for v in vulns
                ]
                port_objs.append(port_data)

            host_objs.append(
                {
                    "ip": host["ip"],
                    "status": host["status"],
                    "ports": port_objs,
                }
            )

        return {
            "scan": dict(scan),
            "hosts": host_objs,
        }
    finally:
        conn.close()


def get_latest_scan_with_vulns() -> Dict[str, Any]:
    conn = _connect()
    try:
        row = conn.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        if not row:
            return {"scan": None, "hosts": []}
        return get_scan_details(int(row["id"]))
    finally:
        conn.close()


# ✅ NEW FUNCTIONS FOR WAZUH

def insert_wazuh_alert(alert: Dict[str, Any]) -> None:
    conn = _connect()
    try:
        conn.execute(
            """
            INSERT OR IGNORE INTO wazuh_alerts
            (alert_time, agent_name, rule_id, rule_level, description, location, path)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.get("time"),
                alert.get("agent"),
                alert.get("rule_id"),
                alert.get("level"),
                alert.get("description"),
                alert.get("location"),
                alert.get("path"),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def list_wazuh_alerts(limit: int = 20) -> List[sqlite3.Row]:
    conn = _connect()
    try:
        cur = conn.execute(
            """
            SELECT * FROM wazuh_alerts
            ORDER BY alert_time DESC
            LIMIT ?
            """,
            (limit,),
        )
        return cur.fetchall()
    finally:
        conn.close()
