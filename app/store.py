from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from .models import Device, Link, utc_now


class DeviceStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._setup()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _setup(self) -> None:
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS devices (
                    ip TEXT PRIMARY KEY, mac TEXT, hostname TEXT, vendor TEXT,
                    state TEXT NOT NULL, role TEXT NOT NULL,
                    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                    open_ports TEXT NOT NULL DEFAULT '[]',
                    os_name TEXT, os_accuracy INTEGER,
                    services TEXT NOT NULL DEFAULT '[]', sources TEXT NOT NULL DEFAULT '[]'
                );
                CREATE TABLE IF NOT EXISTS scan_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL,
                    finished_at TEXT, network TEXT NOT NULL, profile TEXT NOT NULL,
                    status TEXT NOT NULL, device_count INTEGER DEFAULT 0, error TEXT
                );
                CREATE TABLE IF NOT EXISTS observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
                    ip TEXT NOT NULL, state TEXT NOT NULL, snapshot TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    FOREIGN KEY(scan_id) REFERENCES scan_runs(id)
                );
                CREATE TABLE IF NOT EXISTS links (
                    source TEXT NOT NULL, target TEXT NOT NULL, kind TEXT NOT NULL,
                    confidence REAL NOT NULL, evidence TEXT NOT NULL, updated_at TEXT NOT NULL,
                    PRIMARY KEY(source, target, evidence)
                );
            """)
            columns = {row[1] for row in db.execute("PRAGMA table_info(devices)")}
            for name, declaration in {
                "os_name": "TEXT", "os_accuracy": "INTEGER",
                "services": "TEXT NOT NULL DEFAULT '[]'", "sources": "TEXT NOT NULL DEFAULT '[]'",
            }.items():
                if name not in columns:
                    db.execute(f"ALTER TABLE devices ADD COLUMN {name} {declaration}")

    def begin_scan(self, network: str, profile: str) -> int:
        with self._lock, self._connect() as db:
            cursor = db.execute(
                "INSERT INTO scan_runs(started_at,network,profile,status) VALUES(?,?,?,'running')",
                (utc_now(), network, profile),
            )
            return int(cursor.lastrowid)

    def finish_scan(self, scan_id: int, status: str, count: int, error: str | None = None) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                "UPDATE scan_runs SET finished_at=?,status=?,device_count=?,error=? WHERE id=?",
                (utc_now(), status, count, error, scan_id),
            )

    def upsert(self, device: Device, scan_id: int | None = None) -> None:
        services = [service.to_dict() for service in device.services]
        with self._lock, self._connect() as db:
            previous = db.execute("SELECT first_seen FROM devices WHERE ip=?", (device.ip,)).fetchone()
            first_seen = previous["first_seen"] if previous else device.first_seen
            db.execute("""INSERT INTO devices
                (ip,mac,hostname,vendor,state,role,first_seen,last_seen,open_ports,os_name,os_accuracy,services,sources)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(ip) DO UPDATE SET
                  mac=COALESCE(excluded.mac,devices.mac), hostname=COALESCE(excluded.hostname,devices.hostname),
                  vendor=COALESCE(excluded.vendor,devices.vendor), state=excluded.state, role=excluded.role,
                  last_seen=excluded.last_seen, open_ports=excluded.open_ports,
                  os_name=COALESCE(excluded.os_name,devices.os_name),
                  os_accuracy=COALESCE(excluded.os_accuracy,devices.os_accuracy),
                  services=excluded.services, sources=excluded.sources""",
                (device.ip, device.mac, device.hostname, device.vendor, device.state, device.role,
                 first_seen, device.last_seen, json.dumps(device.open_ports), device.os_name,
                 device.os_accuracy, json.dumps(services), json.dumps(device.sources)),
            )
            if scan_id is not None:
                db.execute(
                    "INSERT INTO observations(scan_id,ip,state,snapshot,observed_at) VALUES(?,?,?,?,?)",
                    (scan_id, device.ip, device.state, json.dumps(device.to_dict()), device.last_seen),
                )

    def mark_missing_offline(self, seen_ips: set[str]) -> None:
        with self._lock, self._connect() as db:
            if seen_ips:
                placeholders = ",".join("?" for _ in seen_ips)
                db.execute(f"UPDATE devices SET state='offline' WHERE ip NOT IN ({placeholders})", tuple(seen_ips))

    @staticmethod
    def _device(row: sqlite3.Row) -> dict:
        item = dict(row)
        for name in ("open_ports", "services", "sources"):
            item[name] = json.loads(item.get(name) or "[]")
        return item

    def all(self) -> list[dict]:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM devices ORDER BY state DESC, ip").fetchall()
        return [self._device(row) for row in rows]

    def get(self, ip: str) -> dict | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
        return self._device(row) if row else None

    def scans(self, limit: int = 50) -> list[dict]:
        with self._connect() as db:
            return [dict(row) for row in db.execute(
                "SELECT * FROM scan_runs ORDER BY id DESC LIMIT ?", (min(limit, 200),)
            )]

    def history(self, ip: str, limit: int = 100) -> list[dict]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT scan_id,state,snapshot,observed_at FROM observations WHERE ip=? ORDER BY id DESC LIMIT ?",
                (ip, min(limit, 500)),
            ).fetchall()
        return [{**dict(row), "snapshot": json.loads(row["snapshot"])} for row in rows]

    def replace_observed_links(self, links: list[Link]) -> None:
        with self._lock, self._connect() as db:
            db.execute("DELETE FROM links")
            db.executemany(
                "INSERT INTO links(source,target,kind,confidence,evidence,updated_at) VALUES(?,?,?,?,?,?)",
                [(x.source, x.target, x.kind, x.confidence, x.evidence, utc_now()) for x in links],
            )

    def links(self) -> list[dict]:
        with self._connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM links")]

