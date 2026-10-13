# Wi-Fi Network Map

A local-first network inventory and topology dashboard. It discovers devices on the LAN, records IP/MAC/hostname/ports, tracks online/offline state, and pushes topology updates to the browser in real time.

> Only scan networks you own or are explicitly authorized to assess. The default scanner is intentionally limited to at most 1,024 IPv4 addresses and a small allowlist of common TCP ports.

## What the MVP does

- Detects the computer's local IPv4 address, `/24` network, and default gateway.
- Performs bounded, concurrent ICMP discovery.
- Enriches results from the operating system ARP/neighbor cache.
- Resolves hostnames and checks a small set of common service ports.
- Stores first seen, last seen, current state, IP, MAC, hostname, role, and ports in SQLite.
- Displays a live topology and device inventory; updates arrive over Server-Sent Events.
- Models ordinary Wi-Fi topology honestly: client-to-gateway links are marked as **inferred**.

## Architecture

```text
ping sweep ─┐
ARP cache ──┼─> discovery/enrichment ─> SQLite ─> FastAPI ─> SSE ─> browser SVG map
DNS lookup ─┤
port probe ─┘
```

The collector runs on a machine connected to the target LAN. The HTTP service binds to localhost by default; discovery data does not leave the computer.

## Run it

Requires Python 3.11+ and the system `ping`, `arp` or `ip` command.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>. The first scan starts automatically. To override the conservative `/24` guess:

```bash
NETWORK_CIDR=192.168.1.0/24 SCAN_INTERVAL_SECONDS=60 uvicorn app.main:app
```

API endpoints:

- `GET /api/topology` — current nodes, links, and scan status
- `POST /api/scan` — trigger a discovery pass
- `GET /api/events` — live SSE event stream
- `GET /docs` — interactive OpenAPI documentation

## What each field means

| Field | Source | Reliability |
|---|---|---|
| IP | ICMP response, local host, gateway, ARP cache | High at observation time |
| MAC | OS neighbor/ARP cache | High on the same L2 subnet; unavailable across routers |
| Hostname | Reverse DNS | Best effort |
| Open ports | Short TCP connection probes to an allowlist | Best effort; firewalls can hide services |
| Online | Seen in the latest scan | Probabilistic; some devices ignore ping |
| Link | Gateway-centered inference in the MVP | Not a physical connection claim |

## Implementation roadmap

### Phase 1 — current MVP

The included implementation provides safe discovery, persistence, API, live events, and a responsive map. It avoids raw-packet/root requirements, so it is easy to run on macOS and Linux.

### Phase 2 — higher discovery accuracy

Add pluggable collectors and merge observations rather than replacing records:

- ARP broadcast discovery with Scapy for same-subnet devices that ignore ICMP (requires elevated packet privileges).
- mDNS/Bonjour (`_services._dns-sd._udp.local`) for names and device/service types.
- SSDP/UPnP discovery for TVs, speakers, routers, and media devices.
- DHCP lease import from supported routers.
- Local IEEE OUI database for offline MAC-vendor lookup.
- Optional Nmap adapter for authorized, deeper service and OS fingerprinting.

Every observation should record `source`, `observed_at`, and `confidence`, allowing conflicts to be reconciled safely.

### Phase 3 — real topology

A client on a flat WLAN generally cannot determine which AP or switch port every device uses. Add adapters for infrastructure that exposes this data:

- SNMPv3 bridge forwarding tables and ARP tables from managed switches/routers.
- LLDP/CDP neighbor tables for switch-to-switch and switch-to-AP edges.
- Controller APIs (UniFi, Omada, Aruba, Meraki) for client-to-AP associations, signal, VLAN, and traffic.

Label links `observed` only when supplied by one of these sources. Retain `inferred` and a confidence score for all heuristics.

### Phase 4 — product features

- Device fingerprinting and user-defined names/tags.
- New-device, offline, and vendor-change alerts.
- Historical presence, IP changes, and topology snapshots.
- VLAN/subnet views, search, filters, and device detail panels.
- Authentication, encrypted secrets, audit logs, retention controls, and Docker packaging.
- Prometheus metrics and webhook/email notification adapters.

## Production data model

The MVP keeps one current row per IP for simplicity. A production model should use stable device identities and append-only observations:

```text
Device(id, canonical_mac, user_name, vendor, type, first_seen, last_seen)
Interface(id, device_id, mac, ip, vlan, first_seen, last_seen)
Observation(id, interface_id, source, payload, confidence, observed_at)
Link(id, source_device, target_device, kind, source, confidence, observed_at)
Service(id, interface_id, protocol, port, name, product, version, observed_at)
```

Do not use IP as permanent identity: DHCP changes it, and privacy MAC rotation can also split one physical client into multiple identities.

## Security design

- Bind to `127.0.0.1` unless authentication and TLS are configured.
- Keep scan CIDRs in an explicit allowlist and enforce address-count/rate limits.
- Store SNMP/controller credentials in an OS keychain or secret manager, never SQLite or source control.
- Use SNMPv3 rather than SNMPv2 community strings.
- Treat hostnames and service banners as untrusted input; escape them in the UI.
- Run the web service unprivileged. If raw ARP is added, isolate it in a small capability-limited helper.
- Make active/deep scanning opt-in and preserve an audit trail of who initiated it.

## Known MVP limitations

- `/24` is guessed because interface netmask detection varies by OS; set `NETWORK_CIDR` when needed.
- ICMP-only devices may be missed until they appear in the neighbor table.
- MAC vendor lookup and real AP/switch topology are roadmap items.
- IPv6 discovery is not implemented.
- A record is considered offline after one missed pass; production should require several misses and track scan coverage.
