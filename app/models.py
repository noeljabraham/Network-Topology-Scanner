from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class Service:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    name: str | None = None
    product: str | None = None
    version: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


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
    os_name: str | None = None
    os_accuracy: int | None = None
    services: list[Service] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    @property
    def open_ports(self) -> list[int]:
        return sorted({service.port for service in self.services if service.state == "open"})

    def to_dict(self) -> dict:
        value = asdict(self)
        value["open_ports"] = self.open_ports
        return value


@dataclass(slots=True)
class Link:
    source: str
    target: str
    kind: str = "inferred"
    confidence: float = 0.5
    evidence: str = "gateway inference"

    def to_dict(self) -> dict:
        return asdict(self)

