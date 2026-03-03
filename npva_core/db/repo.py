import os
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional

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

def insert_host(scan_id: int, ip: str, status: str) -> int:
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

def insert_service(host_id: int, svc: Dict[str, Any]) -> int:
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

        hosts = conn.execute("SELECT * FROM hosts WHERE scan_id=?", (scan_id,)).fetchall()
        host_objs: List[Dict[str, Any]] = []
        for h in hosts:
            services = conn.execute("SELECT * FROM services WHERE host_id=?", (h["id"],)).fetchall()
            host_objs.append(
                {
                    "ip": h["ip"],
                    "status": h["status"],
                    "ports": [dict(s) for s in services],
                }
            )

        return {"scan": dict(scan), "hosts": host_objs}
    finally:
        conn.close()
