from __future__ import annotations

import asyncio
import ipaddress
import shutil
import xml.etree.ElementTree as ET

from .models import Device, Service, utc_now


class NmapUnavailable(RuntimeError):
    pass


def available() -> bool:
    return shutil.which("nmap") is not None


async def _run(args: list[str], timeout: int) -> str:
    if not available():
        raise NmapUnavailable("nmap is not installed; install it with: sudo apt install nmap")
    process = await asyncio.create_subprocess_exec(
        "nmap", *args, "-oX", "-", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        raise RuntimeError(f"nmap exceeded the {timeout}s safety timeout")
    if process.returncode:
        raise RuntimeError(stderr.decode(errors="replace").strip() or "nmap failed")
    return stdout.decode(errors="replace")


def parse_xml(xml: str, gateway: str | None = None, local: str | None = None) -> list[Device]:
    root = ET.fromstring(xml)
    devices: list[Device] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        addresses = {node.get("addrtype"): node for node in host.findall("address")}
        ip_node = addresses.get("ipv4")
        if ip_node is None:
            ip_node = addresses.get("ipv6")
        if ip_node is None or not ip_node.get("addr"):
            continue
        ip = ip_node.get("addr", "")
        mac_node = addresses.get("mac")
        hostnames = host.findall("./hostnames/hostname")
        services: list[Service] = []
        for port in host.findall("./ports/port"):
            state, service = port.find("state"), port.find("service")
            services.append(Service(
                port=int(port.get("portid", "0")), protocol=port.get("protocol", "tcp"),
                state=state.get("state", "unknown") if state is not None else "unknown",
                name=service.get("name") if service is not None else None,
                product=service.get("product") if service is not None else None,
                version=service.get("version") if service is not None else None,
            ))
        matches = host.findall("./os/osmatch")
        best = max(matches, key=lambda node: int(node.get("accuracy", "0")), default=None)
        role = "gateway" if ip == gateway else "scanner" if ip == local else "client"
        devices.append(Device(
            ip=ip, mac=mac_node.get("addr", "").lower() if mac_node is not None else None,
            vendor=mac_node.get("vendor") if mac_node is not None else None,
            hostname=hostnames[0].get("name") if hostnames else None, role=role,
            last_seen=utc_now(), services=services,
            os_name=best.get("name") if best is not None else None,
            os_accuracy=int(best.get("accuracy", "0")) if best is not None else None,
            sources=["nmap"],
        ))
    return devices


async def scan(cidr: str, profile: str, gateway: str | None, local: str | None) -> list[Device]:
    network = ipaddress.ip_network(cidr, strict=False)
    if network.num_addresses > 1024:
        raise ValueError("Nmap target may contain at most 1,024 addresses")
    common = ["-n", "--max-retries", "2", "--host-timeout", "45s"]
    if profile == "discovery":
        args, timeout = ["-sn", "-PR", *common, str(network)], 180
    elif profile == "standard":
        args, timeout = ["-sT", "-sV", "--version-light", "--top-ports", "100", "-T4", *common, str(network)], 600
    elif profile == "deep":
        args, timeout = ["-sS", "-sV", "-O", "--traceroute", "--top-ports", "1000", "-T4", *common, str(network)], 1800
    else:
        raise ValueError("profile must be discovery, standard, or deep")
    return parse_xml(await _run(args, timeout), gateway, local)
