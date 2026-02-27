# SNMP MAC Address Collector

Collect MAC address tables (FDB/ARP) from Cisco L2/L3 switches via SNMP, store them in PostgreSQL with full change history, and expose a web UI with role-based access control and audit log.

## Why

- Track which MAC address is on which port/VLAN/switch
- Detect network loops (MAC seen on multiple ports/switches simultaneously)
- Full change history with bitmask flags showing exactly what changed, including disappearances
- SNMP is lightweight compared to SSH — safe to poll 50+ switches every 5 minutes
- Web UI for searching MAC/IP, reviewing change history, and browsing MACs per switch

## Architecture

```
Process 1: Core Switch (192.168.1.1)        Process 2: Access Switches (all others)
ARP table (ipNetToMediaTable)                  FDB table (BRIDGE-MIB + community@vlan)
    |                                              |
    v                                              v
+------------+     +---------------+         +-------------+     +---------------+
| arp_core   | --> | arp_changes   |         | mac_current | --> | mac_changes   |
| (current)  |     | (partitioned) |         | (current)   |     | (partitioned) |
+------------+     +---------------+         +-------------+     +---------------+

                        Web UI (FastAPI + Jinja2 + HTMX)
                               |
                    +----------+----------+
                    |                     |
               auth / session        audit_log
               (users table)         (partitioned)

Both collectors write to:
+------------------+
| collection_log   |  one row per switch per run: duration, MAC counts, errors
| (partitioned)    |
+------------------+
```

**Core switch** — ARP table provides MAC + IP + VLAN + interface mapping.

**Access switches** — FDB table provides MAC + VLAN + interface on access ports only (trunk ports filtered out automatically).

**Web UI** — FastAPI + Jinja2 + HTMX, role-based access (admin / operator / viewer), all actions logged to `audit_log`.

## Production Installation

```bash
sudo ./install.sh
```

The installer:
- Creates system user `mac_collector` (nologin)
- Installs application to `/opt/mac-collector/`
- Creates Python virtualenv and installs dependencies
- Copies config to `/etc/mac-collector/.env`
- Applies `schema.sql` if the database is not yet initialized
- Installs and enables systemd services

```
/opt/mac-collector/       ← application code + venv  (root:root 755)
/etc/mac-collector/.env   ← credentials               (root:mac_collector 640)
```

### systemd services

| Unit | Type | Description |
|------|------|-------------|
| `mac-collector-web.service` | service | uvicorn, port 8000 on 127.0.0.1 |
| `mac-collector-arp.timer` | timer | ARP collector, every 5 min |
| `mac-collector-fdb.timer` | timer | FDB collector, every 5 min |

```bash
# Status
systemctl status mac-collector-web
systemctl list-timers mac-collector-*

# Logs
journalctl -u mac-collector-web -f
journalctl -u mac-collector-arp --since today
```

### After installation

```bash
# Create first admin user
sudo -u mac_collector /opt/mac-collector/venv/bin/python \
    /opt/mac-collector/seed_admin.py --email admin@corp.local
```

## Manual Setup (development)

### Requirements

- Python 3.12+
- `snmpwalk` (net-snmp package)
- PostgreSQL 14+
- SNMP v2c enabled on target switches

```bash
sudo apt install snmp postgresql-client   # Debian/Ubuntu
```

### Database

```bash
# Create user and database
sudo -u postgres psql -c "CREATE USER mac_collector_user WITH PASSWORD 'your_password';"
sudo -u postgres psql -c "CREATE DATABASE mac_collector OWNER mac_collector_user;"

# Apply schema (network tables, auth tables, collection_log, partitions)
psql -U mac_collector_user -d mac_collector -f schema.sql
```

### Python environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Environment variables

Create a `.env` file:

```bash
SNMP_COMMUNITY=public

DB_HOST=localhost
DB_PORT=5432
DB_NAME=mac_collector
DB_USER=mac_collector_user
DB_PASSWORD=your_password

SESSION_SECRET=$(openssl rand -hex 32)

# Optional: timezone for web UI display (default: America/New_York)
DISPLAY_TZ=America/New_York

# Optional: max simultaneous FDB switch polls (default: 10)
FDB_CONCURRENCY=10
```

### Create first admin user

```bash
python seed_admin.py --email admin@corp.local
# prompts for password (min 12 characters)
```

### Run the server

```bash
uvicorn web:app --reload --port 8000
```

Open http://localhost:8000 — you will be redirected to the login page.

## Web UI

### Roles and access

| Role | Capabilities |
|------|-------------|
| **viewer** | Search MAC/IP, view change history, browse MACs on Switches (read-only) |
| **operator** | viewer + add/delete switches, trigger on-demand FDB update, view collector logs |
| **admin** | operator + manage users (create, disable, set role, reset password) + view audit log |

### Pages

| Page | URL | Min Role | Description |
|------|-----|----------|-------------|
| Search | `/` | viewer | Search by MAC or IP address; shows current location and change history |
| MACs on Switches | `/mac-on-switches` | viewer | Browse all MACs learned on a selected switch |
| Switches | `/switches` | operator | Switch registry — add, edit, delete switches |
| Collector Logs | `/collector-logs` | operator | Per-switch poll history: duration, MAC counts, errors |
| Users | `/users` | admin | User management |
| Audit Log | `/audit` | admin | Filterable, searchable, paginated audit trail |
| Profile | `/profile` | viewer | Change own password |

### Routes

| Method | URL | Role | Description |
|--------|-----|------|-------------|
| GET | `/login` | — | Login page |
| POST | `/login` | — | Authenticate |
| POST | `/logout` | viewer+ | End session |
| GET | `/` | viewer+ | Search MAC/IP + change history |
| GET | `/mac-on-switches` | viewer+ | MACs on Switches page |
| GET | `/mac-on-switches/table` | viewer+ | HTMX partial: MAC table for selected switch |
| POST | `/mac-on-switches/update` | operator+ | Trigger live FDB poll, upsert results, return partial |
| GET | `/switches` | operator+ | Switch registry |
| POST | `/switches` | operator+ | Add switch (with IP validation) |
| POST | `/switches/{id}/edit` | admin | Edit switch (with IP validation) |
| POST | `/switches/{id}/delete` | operator+ | Delete switch |
| GET | `/users` | admin | User list |
| POST | `/users` | admin | Create user |
| POST | `/users/{id}/disable` | admin | Disable user |
| POST | `/users/{id}/set-role` | admin | Change user role |
| POST | `/users/{id}/set-password` | admin | Reset user password |
| GET | `/profile` | viewer+ | Change own password |
| GET | `/collector-logs` | operator+ | Collector poll history with filters, pagination |
| GET | `/audit` | admin | Audit log with filters, search, pagination |

`/search` and `/history` redirect to `/` (301).

### MACs on Switches

The **MACs on Switches** page (`/mac-on-switches`) shows the current MAC address table for any switch:

- Select a switch from the dropdown — the table loads automatically via HTMX (no page reload).
- **Update** button (operator+ only) triggers a live SNMP FDB poll on the selected switch, upserts results into the database, and refreshes the table in place.
- Table sorts by interface by default (natural sort: Fa1/0/1 before Fa1/0/10).
- MACs that disappeared from the switch since the last collection appear as `GONE` entries in the change history.

### Collector Logs features

The **Collector Logs** page (`/collector-logs`) shows the result of every SNMP poll run:

- Filter by **collector type** (FDB / ARP), **switch IP** (partial match), **date range**, and **Errors only** toggle.
- **Duration** column shows wall-clock time of the SNMP poll (formatted as `Xms` or `X.Xs`).
- **Changed** / **Gone** counts are highlighted in bold when non-zero; Gone is shown in red.
- **Status** column: green **OK** badge on success, red **ERROR** badge with the first 60 characters of the error message (full message in tooltip) on failure.
- Errors are raised when `snmpwalk` exits non-zero with a non-empty stderr (timeout, no route to host, auth failure). An empty FDB/ARP table on a reachable switch is not an error.
- **Per-page** dropdown: 50 / 100 / 200 / 500 entries.
- Paginated with Prev / Next navigation.

### Audit Log features

- Filter by **action type**, **date range** (From / Until), and free-text **search** (matches any field: user, action, IP, detail, timestamp — using PostgreSQL `ILIKE`).
- **Per-page** dropdown: 50 / 100 / 200 / 500 entries.
- Paginated with Prev / Next navigation.

### Table sorting

All tables support client-side column sorting:
- Click any column header to sort ascending; click again to reverse.
- Sort arrows: ⇅ (unsorted), ▲ (asc), ▼ (desc).
- **Natural sort order** — interface names sort correctly (Fa1/0/1, Fa1/0/2, ..., Fa1/0/10).
- Default sort per page: Search (date desc), MACs on Switches (interface asc), Switches (IP asc), Users (email asc), Collector Logs (time desc), Audit Log (time desc).
- HTMX-loaded tables (MACs on Switches partial) are re-initialized automatically on `htmx:afterSwap`.

### Timezone display

All timestamps in the UI are displayed in the server's local timezone (configured via `DISPLAY_TZ` environment variable, default `America/New_York`). Timestamps are stored as `TIMESTAMPTZ` in UTC in PostgreSQL.

### IP address validation

When adding or editing a switch, the IP address is validated with Python's `ipaddress` module. The following are rejected with an error message:
- Invalid format
- Loopback (127.x.x.x)
- Multicast (224.x.x.x–239.x.x.x)
- Reserved addresses
- Unspecified (0.0.0.0)

## SNMP OIDs Used

### Core switch (ARP)

| OID | Name | Description |
|-----|------|-------------|
| `.1.3.6.1.2.1.4.22.1.2` | ipNetToMediaPhysAddress | MAC address |
| `.1.3.6.1.2.1.4.22.1.4` | ipNetToMediaType | Entry type (dynamic=3, static=4) |
| `.1.3.6.1.2.1.31.1.1.1.1` | ifName | Interface name |

### Access switches (FDB)

| OID | Name | Description |
|-----|------|-------------|
| `.1.3.6.1.4.1.9.9.68.1.2.2.1.2` | vmVlan | Data VLAN assignment per ACCESS port (ifIndex → VLAN ID) |
| `.1.3.6.1.4.1.9.9.68.1.5.1.1.1` | vmVoiceVlanId | Voice VLAN assignment per ACCESS port; values 0 / 4095 / 4096 filtered |
| `.1.3.6.1.2.1.17.4.3.1.1` | dot1dTpFdbAddress | MAC address (per-VLAN via `community@vlan`) |
| `.1.3.6.1.2.1.17.4.3.1.2` | dot1dTpFdbPort | Bridge port number |
| `.1.3.6.1.2.1.17.1.4.1.2` | dot1dBasePortIfIndex | Bridge port to ifIndex mapping |
| `.1.3.6.1.4.1.9.9.46.1.6.1.1.13` | vlanTrunkPortDynamicState | Port mode (trunk/access) |
| `.1.3.6.1.4.1.9.9.46.1.6.1.1.14` | vlanTrunkPortDynamicStatus | Actual trunk status |
| `.1.3.6.1.4.1.9.9.46.1.3.1.1.2` | vtpVlanState | Active VLAN discovery (retained, not used in collect) |

VLAN discovery uses `vmVlan` + `vmVoiceVlanId` instead of a full `vtpVlanState` walk — FDB is polled only for VLANs that have at least one ACCESS port assigned, reducing SNMP traffic significantly.

**Important:** `dot1dTpFdbAddress` and `dot1dTpFdbPort` are both indexed by the full 6-octet MAC address in the OID suffix (e.g., `.1.2.3.4.5.6`). The join between MAC addresses and bridge port numbers uses this 6-octet suffix as the key — not the last octet alone.

## Database Schema

All tables are in `schema.sql` in a single `BEGIN / COMMIT` transaction.

**Current state tables** (`arp_core`, `mac_current`) — one row per MAC, arrays for multi-value fields (handles loops):

```
mac_address:  AA:BB:CC:DD:EE:FF
switch_ips:   {192.168.1.15, 192.168.1.200}
vlan_ids:     {100, 200}
interfaces:   {Gi1/0/5, Gi2/0/10}
```

**Change log tables** (`arp_changes`, `mac_changes`) — partitioned by week, never deleted. Written only when topology changes:

| change_flags | What changed |
|--------------|--------------|
| 7 (4+2+1) | IP/switch + VLAN + interface |
| 4 | Only IP/switch |
| 2 | Only VLAN |
| 1 | Only interface |
| 0 | MAC disappeared from switch (GONE) |

**Operational log table** (`collection_log`) — one row per switch per poll run, partitioned by week, never deleted:

| Column | Description |
|--------|-------------|
| `collector` | `'fdb'` or `'arp'` |
| `switch_ip` | Switch management IP |
| `duration_ms` | Wall-clock time of the SNMP poll |
| `macs_total` | Entries returned by the collector (`NULL` on error) |
| `macs_changed` | New + topology-changed MACs written to DB |
| `macs_gone` | MACs that disappeared since last poll (FDB only) |
| `error` | `NULL` = success; error message from `snmpwalk` stderr otherwise |

**Auth tables** (`users`, `audit_log`):

| Table | Description |
|-------|-------------|
| `users` | Email + bcrypt password + role (admin/operator/viewer) + enabled flag |
| `audit_log` | Every user action, partitioned by week, never deleted |

**Partitioning:** weekly partitions created automatically via `create_weekly_partitions()`. On startup, the web app calls `ensure_partitions(4)` to create 4 weeks ahead. All partitioned tables: `arp_changes`, `mac_changes`, `collection_log`, `audit_log`.

**Primary keys:** UUID v7 (RFC 9562) generated application-side. Time-ordered for B-tree index locality.

## MAC Disappearance Detection (FLAG_GONE)

When `fdb_collector` upserts a new batch of MACs for a switch, it compares the incoming set against the previously stored MACs for that switch. Any MAC present in the database but absent from the new collection is recorded in `mac_changes` with `change_flags = 0` (FLAG_GONE). The MAC is then removed from `mac_current` (or its switch_ip entry removed if it appears on multiple switches).

MAC addresses are compared case-insensitively (PostgreSQL stores `macaddr` in lowercase; the collector normalises before comparison).

These GONE entries appear in the change history with a grey **GONE** badge.

## Trunk Port Detection

Ports are classified using Cisco VTP MIB:

| vlanTrunkPortDynamicState | vlanTrunkPortDynamicStatus | Result |
|---------------------------|---------------------------|--------|
| on (1) / nonegotiate (5) | *any* | **TRUNK** |
| off (2) | *any* | **ACCESS** |
| desirable (3) / auto (4) | trunking (1) | **TRUNK** |
| desirable (3) / auto (4) | notTrunking (2) | **ACCESS** |

Only MAC addresses learned on ACCESS ports are collected.

## FDB Collector Concurrency

`fdb_collector` polls all access switches in parallel using `asyncio.gather` + `asyncio.Semaphore`. The semaphore limits simultaneous SNMP polls to avoid overloading the network.

```
switch_ips = [sw1, sw2, ..., swN]
          |
    asyncio.gather()          ← all N tasks submitted at once
          |
    Semaphore(10)             ← at most 10 running simultaneously
    /    |    \   ...
  sw1   sw2   sw3            ← each runs collect_async() in a thread
```

Configure via environment variable:

```bash
FDB_CONCURRENCY=10   # default; increase for faster polling of 20–40 switches
```

Each poll result is logged to `collection_log` independently — a timeout on one switch does not affect the others.

## Standalone Diagnostic Scripts

Work independently without the database. All scripts load `.env` from the same directory automatically.

```bash
# Show port modes (trunk/access) on a switch
python3 snmp_ports.py 192.168.1.200

# Collect FDB (MAC table) from access ports
python3 snmp_fdb.py 192.168.1.200         # all VLANs -> file
python3 snmp_fdb.py 192.168.1.200 323     # VLAN 323 -> stdout

# Collect ARP table
python3 snmp_arp.py 192.168.1.1           # all -> file
python3 snmp_arp.py 192.168.1.1 100       # VLAN 100 -> stdout

# Show raw MAC list
python3 snmp_mac_list.py 192.168.1.200
```

## Running Tests

```bash
# Unit + integration tests (no DB required)
python -m pytest tests/test_auth.py tests/test_web.py -v

# Full DB tests (requires running PostgreSQL with schema applied)
export $(cat .env | xargs)
python -m pytest tests/test_db.py tests/test_arp_collector.py tests/test_fdb_collector.py -v
```
