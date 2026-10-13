from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .scanner import discover
from .store import DeviceStore


ROOT = Path(__file__).resolve().parent.parent
store = DeviceStore(ROOT / "network_map.db")
events: set[asyncio.Queue[str]] = set()
scan_lock = asyncio.Lock()
scan_state = {"running": False, "last_error": None, "network": None}


def topology() -> dict:
    devices = store.all()
    gateway = next((d for d in devices if d["role"] == "gateway"), None)
    links = []
    if gateway:
        links = [
            {"source": gateway["ip"], "target": d["ip"], "kind": "inferred", "confidence": 0.5}
            for d in devices
            if d["ip"] != gateway["ip"] and d["state"] == "online"
        ]
    return {"devices": devices, "links": links, "scan": scan_state}


async def publish(payload: dict) -> None:
    message = json.dumps(payload)
    for queue in list(events):
        await queue.put(message)


async def run_scan(cidr: str | None = None) -> None:
    if scan_lock.locked():
        return
    async with scan_lock:
        scan_state.update(running=True, last_error=None)
        await publish({"type": "scan", "state": "started"})
        try:
            info, devices = await discover(cidr)
            seen = {device.ip for device in devices}
            for device in devices:
                store.upsert(device)
            store.mark_missing_offline(seen)
            scan_state["network"] = str(info.network)
            await publish({"type": "topology", "data": topology()})
        except Exception as exc:
            scan_state["last_error"] = str(exc)
            await publish({"type": "scan", "state": "failed", "error": str(exc)})
        finally:
            scan_state["running"] = False
            await publish({"type": "scan", "state": "finished"})


async def scan_loop() -> None:
    interval = max(15, int(os.getenv("SCAN_INTERVAL_SECONDS", "60")))
    while True:
        await run_scan(os.getenv("NETWORK_CIDR"))
        await asyncio.sleep(interval)


@asynccontextmanager
async def lifespan(_: FastAPI):
    task = asyncio.create_task(scan_loop())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="Wi-Fi Network Map", version="0.1.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/topology")
async def get_topology() -> dict:
    return topology()


@app.post("/api/scan", status_code=202)
async def start_scan() -> dict:
    if scan_lock.locked():
        raise HTTPException(status_code=409, detail="A scan is already running")
    asyncio.create_task(run_scan(os.getenv("NETWORK_CIDR")))
    return {"accepted": True}


@app.get("/api/events")
async def event_stream() -> StreamingResponse:
    queue: asyncio.Queue[str] = asyncio.Queue()
    events.add(queue)

    async def stream():
        try:
            yield f"data: {json.dumps({'type': 'topology', 'data': topology()})}\n\n"
            while True:
                message = await queue.get()
                yield f"data: {message}\n\n"
        finally:
            events.discard(queue)

    return StreamingResponse(stream(), media_type="text/event-stream")

