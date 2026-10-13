# Wi-Fi Network Map

A Kali/Linux-focused network inventory and live topology application for networks you own or are explicitly authorized to assess. It combines Nmap with operating-system neighbor data, retains scan history in SQLite, and displays confidence-labelled topology in a browser.

## Capabilities

- Nmap discovery, standard service, and privileged deep scan profiles
- IPv4/MAC address, vendor, hostname, open-port, service/version, and OS-fingerprint import
- Native ping/neighbor-cache fallback when Nmap is unavailable
- First/last seen and online/offline inventory
- Scan-run audit history and per-device snapshots
- Live Server-Sent Events dashboard
- Observed versus inferred topology edges
- Vendor-neutral controller/SNMP/LLDP topology import
- CSV export, optional bearer-token protection, SQLite WAL persistence
- `/22` maximum target and Nmap retry/host-timeout limits
- Kali installer and Docker packaging

No scanner can guarantee that every device is visible. Sleeping clients, Wi-Fi isolation, VLANs, firewalls, NAT, and IPv6-only hosts can hide devices. Nmap also cannot identify an exact access point or switch port without infrastructure data.

## Architecture

```text
Nmap XML ───────────────┐
Linux neighbor cache ──┼──> normalized devices/services ──> SQLite history
native fallback ───────┘                                  │
                                                          ├─> REST + CSV
controller/SNMP/LLDP JSON ──> observed topology edges ────┴─> SSE dashboard
```

## Kali installation

```bash
chmod +x scripts/install-kali.sh
./scripts/install-kali.sh
cp .env.example .env
source .venv/bin/activate
NETWORK_CIDR=192.168.1.0/24 uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>. Replace the CIDR with the authorized local network shown by `ip route`. Do not blindly copy the example range.

### Scan profiles

| Profile | Nmap behavior | Privilege | Use |
|---|---|---|---|
| `discovery` | ARP/ping host discovery | Usually unprivileged | Frequent presence checks |
| `standard` | TCP connect, top 100 ports, light version detection | Unprivileged | Normal inventory |
| `deep` | SYN, top 1,000 ports, versions, OS and traceroute | Root or `CAP_NET_RAW` | Infrequent authorized assessment |

The dashboard launches Nmap directly with fixed arguments; the user cannot inject arbitrary command-line flags. Deep scanning is intentionally never the default automatic profile.

## Configuration

Copy `.env.example` or export variables before starting:

| Variable | Default | Meaning |
|---|---|---|
| `NETWORK_CIDR` | detected address `/24` | Explicit authorized target, maximum `/22` |
| `SCAN_ENGINE` | `nmap` | `nmap` or `native` |
| `SCAN_PROFILE` | `discovery` | Automatic scan profile |
| `SCAN_INTERVAL_SECONDS` | `300` | Automatic interval, minimum 30 seconds |
| `AUTO_SCAN` | `true` | Enable scheduled scanning |
| `API_TOKEN` | empty | Protect API when set |
| `DATABASE_PATH` | `network_map.db` | SQLite location |
| `TOPOLOGY_FILE` | empty | Verified topology JSON path |

If `API_TOKEN` is set, open `http://127.0.0.1:8000/?token=YOUR_TOKEN` once. The UI stores it in browser local storage and sends it with requests. Prefer a reverse proxy with TLS if the interface is exposed beyond localhost.

## API

- `GET /api/health` — Nmap availability and detected network
- `GET /api/topology` — devices, evidence-labelled links, scan state
- `GET /api/devices/{ip}` — device and historical snapshots
- `GET /api/scans` — scan audit history
- `POST /api/scan` — launch a `discovery`, `standard`, or `deep` scan
- `GET /api/export.csv` — current inventory export
- `GET /api/events` — live event stream
- `GET /docs` — generated OpenAPI documentation

Example:

```bash
curl -X POST http://127.0.0.1:8000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"profile":"standard","engine":"nmap"}'
```

## Exact topology

The application labels gateway-to-client edges as `inferred` with 50% confidence. To supply real associations, export switch/controller evidence into the interchange format shown in `topology.example.json` and set `TOPOLOGY_FILE`.

```json
[
  {
    "source": "192.168.1.1",
    "target": "192.168.1.20",
    "kind": "observed",
    "confidence": 1.0,
    "evidence": "UniFi client-to-AP association"
  }
]
```

Typical producers are UniFi/Omada/Meraki controller APIs, SNMPv3 bridge forwarding tables, and LLDP/CDP neighbor tables. Observed edges override inferred edges for the same target. This boundary is deliberate: the program never presents a guessed physical connection as fact.

For Docker, either bake the generated file into an image or add a read-only bind mount and set `TOPOLOGY_FILE` to its path inside the container.

## Docker

Docker host networking is intended for Linux because discovery broadcasts must reach the LAN:

```bash
cp .env.example .env
# Edit NETWORK_CIDR in .env first.
docker compose up --build -d
```

The container runs as an unprivileged user. `NET_RAW`/`NET_ADMIN` capabilities are included for deep scans and may be removed when only discovery/standard profiles are used.

## Security model

- Only scan systems for which you have authorization.
- Keep the service on `127.0.0.1` unless token authentication and TLS are configured.
- Target size, retries, per-host duration, and total scan duration are bounded.
- Nmap arguments are selected from fixed profiles; request data never becomes shell syntax.
- Hostnames and service information are rendered with `textContent`, not HTML.
- Infrastructure credentials are not stored by this application. A separate adapter should write sanitized link JSON.
- SQLite history may reveal device presence patterns; protect and periodically rotate the database.

## Tests

```bash
python3 -m unittest discover -s tests -v
node --check static/app.js
python3 -m compileall -q app tests
```

The unit suite covers database updates, history/offline behavior, scan-range restrictions, and Nmap XML parsing. Integration scans require Nmap and an explicitly authorized test network.
