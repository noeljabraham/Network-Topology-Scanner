from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from .models import Device


class DeviceStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._setup()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _setup(self) -> None:
        with self._connect() as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    ip TEXT PRIMARY KEY,
                    mac TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    state TEXT NOT NULL,
                    role TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    open_ports TEXT NOT NULL DEFAULT '[]'
                )
                """
            )

    def upsert(self, device: Device) -> None:
        with self._lock, self._connect() as db:
            previous = db.execute(
                "SELECT first_seen FROM devices WHERE ip = ?", (device.ip,)
            ).fetchone()
            first_seen = previous["first_seen"] if previous else device.first_seen
            db.execute(
                """
                INSERT INTO devices
                    (ip, mac, hostname, vendor, state, role, first_seen, last_seen, open_ports)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    mac=COALESCE(excluded.mac, devices.mac),
                    hostname=COALESCE(excluded.hostname, devices.hostname),
                    vendor=COALESCE(excluded.vendor, devices.vendor),
                    state=excluded.state,
                    role=excluded.role,
                    last_seen=excluded.last_seen,
                    open_ports=excluded.open_ports
                """,
                (
                    device.ip,
                    device.mac,
                    device.hostname,
                    device.vendor,
                    device.state,
                    device.role,
                    first_seen,
                    device.last_seen,
                    json.dumps(device.open_ports),
                ),
            )

    def mark_missing_offline(self, seen_ips: set[str]) -> None:
        with self._lock, self._connect() as db:
            if not seen_ips:
                return
            placeholders = ",".join("?" for _ in seen_ips)
            db.execute(
                f"UPDATE devices SET state='offline' WHERE ip NOT IN ({placeholders})",
                tuple(seen_ips),
            )

    def all(self) -> list[dict]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM devices ORDER BY state DESC, ip"
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["open_ports"] = json.loads(item["open_ports"])
            result.append(item)
        return result

