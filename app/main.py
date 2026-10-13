from __future__ import annotations

import asyncio
import csv
import io
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import nmap_scanner
from .models import Device
from .scanner import discover, network_info
from .store import DeviceStore
from .topology import inferred_links, load_verified_links


ROOT = Path(__file__).resolve().parent.parent
store = DeviceStore(Path(os.getenv("DATABASE_PATH", ROOT / "network_map.db")))
events: set[asyncio.Queue[str]] = set()
scan_lock = asyncio.Lock()
scan_state: dict = {
    "running": False, "last_error": None, "network": None,
    "profile": None, "engine": None, "progress": None,
    "local_ip": None, "gateway": None,
}


class ScanRequest(BaseModel):
    profile: str = "standard"
    engine: str = "nmap"


def merge_devices(primary: list[Device], supplemental: list[Device]) -> list[Device]:
    """Combine evidence without allowing lower-detail probes to erase Nmap data."""
    merged = {device.ip: device for device in primary}
    for extra in supplemental:
        current = merged.get(extra.ip)
        if current is None:
            merged[extra.ip] = extra
            continue
        current.mac = current.mac or extra.mac
        current.hostname = current.hostname or extra.hostname
        current.vendor = current.vendor or extra.vendor
        if current.role == "client" and extra.role != "client":
            current.role = extra.role
        if not current.services:
            current.services = extra.services
        current.sources = sorted(set(current.sources + extra.sources))
    return list(merged.values())


async def authorize(
    authorization: str | None = Header(default=None), token: str | None = Query(default=None)
) -> None:
    expected = os.getenv("API_TOKEN")
    if expected and authorization != f"Bearer {expected}" and token != expected:
        raise HTTPException(status_code=401, detail="Valid bearer token required")


def topology() -> dict:
    devices = store.all()
    observed = store.links()
    covered = {link["target"] for link in observed}
    inferred = [link.to_dict() for link in inferred_links(devices) if link.target not in covered]
    links = observed + inferred
    return {"devices": devices, "links": links, "scan": dict(scan_state)}


async def publish(payload: dict) -> None:
    message = json.dumps(payload)
    for queue in list(events):
        if queue.qsize() < 10:
            await queue.put(message)


async def run_scan(cidr: str | None = None, profile: str = "standard", engine: str = "nmap") -> None:
    if scan_lock.locked():
        return
    async with scan_lock:
        info = network_info(cidr)
        network = str(info.network)
        scan_id = store.begin_scan(network, profile)
        scan_state.update(
            running=True, last_error=None, network=network, profile=profile,
            engine=engine, progress="scanning", local_ip=info.local_ip, gateway=info.gateway,
        )
        await publish({"type": "scan", "state": "started", "profile": profile})
        devices = []
        try:
            if engine == "nmap":
                devices = await nmap_scanner.scan(network, profile, info.gateway, info.local_ip)
                # Ping and the neighbor cache find devices that expose no TCP ports,
                # while Nmap provides richer data for hosts that do respond.
                _, supplemental = await discover(network)
                devices = merge_devices(devices, supplemental)
            elif engine == "native":
                _, devices = await discover(network)
            else:
                raise ValueError("engine must be nmap or native")
            scan_state["progress"] = "saving"
            seen = {device.ip for device in devices}
            for device in devices:
                store.upsert(device, scan_id)
            store.mark_missing_offline(seen)
            verified = load_verified_links(os.getenv("TOPOLOGY_FILE"), seen)
            if verified:
                store.replace_observed_links(verified)
            store.finish_scan(scan_id, "completed", len(devices))
            await publish({"type": "topology", "data": topology()})
        except Exception as exc:
            error = str(exc)
            scan_state["last_error"] = error
            store.finish_scan(scan_id, "failed", len(devices), error)
            await publish({"type": "scan", "state": "failed", "error": error})
        finally:
            scan_state.update(running=False, progress=None)
            await publish({"type": "scan", "state": "finished"})


async def scan_loop() -> None:
    interval = max(30, int(os.getenv("SCAN_INTERVAL_SECONDS", "300")))
    await asyncio.sleep(1)
    while True:
        await run_scan(os.getenv("NETWORK_CIDR"), os.getenv("SCAN_PROFILE", "discovery"), os.getenv("SCAN_ENGINE", "nmap"))
        await asyncio.sleep(interval)


@asynccontextmanager
async def lifespan(_: FastAPI):
    task = None
    if os.getenv("AUTO_SCAN", "true").lower() == "true":
        task = asyncio.create_task(scan_loop())
    yield
    if task:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="Wi-Fi Network Map", version="1.0.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/health")
async def health(_: None = Depends(authorize)) -> dict:
    info = network_info(os.getenv("NETWORK_CIDR"))
    return {
        "status": "ok", "version": app.version, "nmap_available": nmap_scanner.available(),
        "network": str(info.network), "gateway": info.gateway, "local_ip": info.local_ip,
    }


@app.get("/api/topology")
async def get_topology(_: None = Depends(authorize)) -> dict:
    return topology()


@app.get("/api/devices/{ip}")
async def get_device(ip: str, _: None = Depends(authorize)) -> dict:
    device = store.get(ip)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return {"device": device, "history": store.history(ip)}


@app.get("/api/scans")
async def get_scans(limit: int = 50, _: None = Depends(authorize)) -> list[dict]:
    return store.scans(limit)


@app.post("/api/scan", status_code=202)
async def start_scan(request: ScanRequest, _: None = Depends(authorize)) -> dict:
    if scan_lock.locked():
        raise HTTPException(status_code=409, detail="A scan is already running")
    if request.profile not in {"discovery", "standard", "deep"}:
        raise HTTPException(status_code=422, detail="Unknown scan profile")
    if request.engine not in {"nmap", "native"}:
        raise HTTPException(status_code=422, detail="Unknown scan engine")
    asyncio.create_task(run_scan(os.getenv("NETWORK_CIDR"), request.profile, request.engine))
    return {"accepted": True, "profile": request.profile, "engine": request.engine}


@app.get("/api/export.csv", response_class=PlainTextResponse)
async def export_csv(_: None = Depends(authorize)) -> PlainTextResponse:
    output = io.StringIO()
    fields = ["ip", "mac", "hostname", "vendor", "state", "role", "os_name", "open_ports", "first_seen", "last_seen"]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for device in store.all():
        writer.writerow({key: ",".join(map(str, device[key])) if key == "open_ports" else device.get(key) for key in fields})
    return PlainTextResponse(
        output.getvalue(), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=network-map.csv"},
    )


@app.get("/api/events")
async def event_stream(_: None = Depends(authorize)) -> StreamingResponse:
    queue: asyncio.Queue[str] = asyncio.Queue(maxsize=10)
    events.add(queue)

    async def stream():
        try:
            yield f"data: {json.dumps({'type': 'topology', 'data': topology()})}\n\n"
            while True:
                try:
                    message = await asyncio.wait_for(queue.get(), timeout=20)
                    yield f"data: {message}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            events.discard(queue)

    return StreamingResponse(stream(), media_type="text/event-stream")
