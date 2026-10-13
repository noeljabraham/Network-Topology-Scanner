from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class Device:
    ip: str
    mac: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    state: str = "online"
    role: str = "client"
    first_seen: str = field(default_factory=utc_now)
    last_seen: str = field(default_factory=utc_now)
    open_ports: list[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class Link:
    source: str
    target: str
    kind: str = "inferred"
    confidence: float = 0.5

    def to_dict(self) -> dict:
        return asdict(self)

