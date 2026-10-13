from __future__ import annotations

import ipaddress
import json
from pathlib import Path

from .models import Link


def inferred_links(devices: list[dict]) -> list[Link]:
    online = [device for device in devices if device["state"] == "online"]
    gateway = next((device for device in online if device["role"] == "gateway"), None)
    if not gateway:
        return []
    return [Link(gateway["ip"], device["ip"]) for device in online if device["ip"] != gateway["ip"]]


def load_verified_links(path: str | None, known_ips: set[str]) -> list[Link]:
    """Load controller/SNMP/LLDP output from a vendor-neutral JSON interchange file."""
    if not path:
        return []
    source = Path(path)
    if not source.exists():
        raise ValueError(f"Topology file does not exist: {source}")
    payload = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(payload, list) or len(payload) > 4096:
        raise ValueError("Topology file must be a JSON list of at most 4,096 links")
    links: list[Link] = []
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("Every topology link must be an object")
        source_ip, target_ip = str(item.get("source", "")), str(item.get("target", ""))
        ipaddress.ip_address(source_ip)
        ipaddress.ip_address(target_ip)
        # External infrastructure nodes are allowed, but endpoint syntax is still validated.
        confidence = float(item.get("confidence", 1.0))
        links.append(Link(
            source=source_ip, target=target_ip, kind=str(item.get("kind", "observed")),
            confidence=min(1.0, max(0.0, confidence)),
            evidence=str(item.get("evidence", "controller-import"))[:160],
        ))
    return links
