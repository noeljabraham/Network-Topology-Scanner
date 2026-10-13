from __future__ import annotations

import asyncio
import ipaddress
import json
import platform
import re
import socket
import subprocess
from dataclasses import dataclass

from .models import Device, Service, utc_now


MAC_PATTERN = re.compile(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
COMMON_PORTS = (22, 53, 80, 443, 445, 548, 631, 1883, 8000, 8080, 8443)


@dataclass(slots=True)
class NetworkInfo:
    local_ip: str
    network: ipaddress.IPv4Network
    gateway: str | None


def local_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("1.1.1.1", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def interface_addresses() -> list[str]:
    """Return configured IPv4 interface addresses without third-party packages."""
    try:
        output = subprocess.check_output(
            ["ip", "-j", "-4", "addr", "show"], text=True,
            stderr=subprocess.DEVNULL, timeout=2,
        )
        return [
            item["local"]
            for interface in json.loads(output)
            for item in interface.get("addr_info", [])
            if item.get("family") == "inet" and item.get("local")
        ]
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, KeyError):
        pass
    try:
        output = subprocess.check_output(
            ["ifconfig"], text=True, stderr=subprocess.DEVNULL, timeout=2
        )
        return re.findall(r"\binet\s+(\d+(?:\.\d+){3})", output)
    except (OSError, subprocess.SubprocessError):
        return []


def default_gateway() -> str | None:
    commands = (
        ["route", "-n", "get", "default"],
        ["ip", "route", "show", "default"],
        ["ip", "route", "get", "1.1.1.1"],
    )
    for command in commands:
        try:
            output = subprocess.check_output(
                command, text=True, stderr=subprocess.DEVNULL, timeout=2
            )
        except (OSError, subprocess.SubprocessError):
            continue
        match = re.search(r"(?:gateway:\s*|default via\s+)(\d+(?:\.\d+){3})", output)
        if match:
            return match.group(1)
    return None


def network_info(cidr: str | None = None) -> NetworkInfo:
    fallback_ip = local_ip()
    candidates = [value for value in interface_addresses() if value != "127.0.0.1"]
    seed_ip = fallback_ip if fallback_ip != "127.0.0.1" else (candidates[0] if candidates else fallback_ip)
    # /24 remains a conservative cross-platform fallback. When an explicit CIDR
    # is supplied, choose the actual interface address belonging to that network.
    network = ipaddress.ip_network(cidr or f"{seed_ip}/24", strict=False)
    if network.num_addresses > 1024:
        raise ValueError("Scan ranges larger than /22 are disabled for safety")
    ip = next((value for value in candidates if ipaddress.ip_address(value) in network), seed_ip)
    return NetworkInfo(ip, network, default_gateway())


async def ping(ip: str) -> bool:
    flag = "-n" if platform.system() == "Windows" else "-c"
    timeout_args = ["-W", "350"] if platform.system() == "Darwin" else ["-W", "1"]
    process = await asyncio.create_subprocess_exec(
        "ping", flag, "1", *timeout_args, ip,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        return await asyncio.wait_for(process.wait(), timeout=1.5) == 0
    except asyncio.TimeoutError:
        process.kill()
        return False


def neighbor_table() -> dict[str, str]:
    commands = (["arp", "-an"], ["ip", "neigh", "show"])
    result: dict[str, str] = {}
    for command in commands:
        try:
            output = subprocess.check_output(
                command, text=True, stderr=subprocess.DEVNULL, timeout=3
            )
        except (OSError, subprocess.SubprocessError):
            continue
        for line in output.splitlines():
            ip_match = re.search(r"\b\d+(?:\.\d+){3}\b", line)
            mac_match = MAC_PATTERN.search(line)
            if ip_match and mac_match:
                result[ip_match.group(0)] = mac_match.group(0).lower().replace("-", ":")
        if result:
            break
    return result


async def resolve_hostname(ip: str) -> str | None:
    try:
        host, _, _ = await asyncio.wait_for(
            asyncio.to_thread(socket.gethostbyaddr, ip), timeout=0.7
        )
        return host
    except (OSError, asyncio.TimeoutError):
        return None


async def open_ports(ip: str) -> list[int]:
    async def check(port: int) -> int | None:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=0.18
            )
            writer.close()
            await writer.wait_closed()
            return port
        except (OSError, asyncio.TimeoutError):
            return None

    values = await asyncio.gather(*(check(port) for port in COMMON_PORTS))
    return [port for port in values if port is not None]


async def discover(cidr: str | None = None) -> tuple[NetworkInfo, list[Device]]:
    info = network_info(cidr)
    semaphore = asyncio.Semaphore(48)

    async def probe(address: ipaddress.IPv4Address) -> str | None:
        async with semaphore:
            value = str(address)
            return value if await ping(value) else None

    responsive = await asyncio.gather(*(probe(ip) for ip in info.network.hosts()))
    ips = {ip for ip in responsive if ip}
    ips.add(info.local_ip)
    if info.gateway:
        ips.add(info.gateway)

    neighbors = neighbor_table()
    ips.update(ip for ip in neighbors if ipaddress.ip_address(ip) in info.network)

    async def enrich(ip: str) -> Device:
        hostname, ports = await asyncio.gather(resolve_hostname(ip), open_ports(ip))
        role = "gateway" if ip == info.gateway else "scanner" if ip == info.local_ip else "client"
        return Device(
            ip=ip,
            mac=neighbors.get(ip),
            hostname=hostname,
            role=role,
            last_seen=utc_now(),
            services=[Service(port=port) for port in ports],
            sources=["ping", "neighbor-cache" if ip in neighbors else "tcp-probe"],
        )

    devices = await asyncio.gather(*(enrich(ip) for ip in sorted(ips, key=ipaddress.ip_address)))
    return info, list(devices)

