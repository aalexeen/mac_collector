"""Database layer for MAC Address Collector. PostgreSQL via asyncpg."""

import asyncio
import hashlib
import json
import os
import uuid as _uuid
from dataclasses import dataclass, field
from datetime import datetime

import asyncpg

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


def _uuid7():
    """UUID v7: Python 3.14+ native, fallback to uuid_utils, then uuid4."""
    if hasattr(_uuid, "uuid7"):
        return __uuid7()
    try:
        import uuid_utils
        return uuid_utils.uuid7()
    except ImportError:
        return _uuid.uuid4()


@dataclass
class ArpEntry:
    mac_address: str
    ip_addresses: list[str] = field(default_factory=list)
    vlan_ids: list[int] = field(default_factory=list)
    interfaces: list[str] = field(default_factory=list)


@dataclass
class MacEntry:
    mac_address: str
    switch_ips: list[str] = field(default_factory=list)
    vlan_ids: list[int] = field(default_factory=list)
    interfaces: list[str] = field(default_factory=list)


# change_flags bitmask
FLAG_IP = 4       # arp_changes: ip changed,   mac_changes: switch_ip changed
FLAG_VLAN = 2     # vlan changed
FLAG_IFACE = 1    # interface changed
FLAG_GONE = 0     # MAC disappeared from switch (no topology bits set)


def _to_str_list(arr) -> list[str]:
    """Normalize DB array (IPv4Address, int, str) to sorted list of strings."""
    return sorted(str(x) for x in arr)


def _topology_hash(*arrays) -> str:
    """MD5 of sorted arrays concatenated."""
    parts = []
    for arr in arrays:
        parts.append(str(sorted(str(x) for x in arr)))
    return hashlib.md5("|".join(parts).encode()).hexdigest()


class Database:
    def __init__(self):
        self._pool: asyncpg.Pool | None = None

    @property
    def dsn(self) -> str:
        host = os.environ.get("DB_HOST", "localhost")
        port = os.environ.get("DB_PORT", "5432")
        name = os.environ.get("DB_NAME", "mac_collector")
        user = os.environ.get("DB_USER", "mac_collector_user")
        password = os.environ.get("DB_PASSWORD", "")
        return f"postgresql://{user}:{password}@{host}:{port}/{name}"

    async def connect(self):
        self._pool = await asyncpg.create_pool(self.dsn, min_size=2, max_size=10)

    async def close(self):
        if self._pool:
            await self._pool.close()

    async def ensure_partitions(self, weeks_ahead: int = 4):
        async with self._pool.acquire() as conn:
            await conn.fetchval(
                "SELECT create_weekly_partitions('arp_changes', $1)", weeks_ahead
            )
            await conn.fetchval(
                "SELECT create_weekly_partitions('mac_changes', $1)", weeks_ahead
            )
            await conn.fetchval(
                "SELECT create_weekly_partitions('audit_log', $1)", weeks_ahead
            )
            await conn.fetchval(
                "SELECT create_weekly_partitions('collection_log', $1)", weeks_ahead
            )

    # ------------------------------------------------------------------
    # Switches
    # ------------------------------------------------------------------

    async def get_switches(self, is_core: bool | None = None) -> list[asyncpg.Record]:
        sql = "SELECT * FROM switches WHERE enabled = true"
        args = []
        if is_core is not None:
            sql += " AND is_core = $1"
            args.append(is_core)
        async with self._pool.acquire() as conn:
            return await conn.fetch(sql, *args)

    async def add_switch(self, ip: str, hostname: str = None, is_core: bool = False):
        async with self._pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO switches (id, ip_address, hostname, is_core)
                   VALUES ($1, $2, $3, $4)""",
                _uuid7(), ip, hostname, is_core,
            )

    async def get_switch_by_id(self, switch_id) -> asyncpg.Record | None:
        async with self._pool.acquire() as conn:
            return await conn.fetchrow(
                "SELECT * FROM switches WHERE id = $1", str(switch_id)
            )

    async def update_switch(self, switch_id, ip: str, hostname: str | None, is_core: bool) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE switches SET ip_address = $1, hostname = $2, is_core = $3 WHERE id = $4",
                ip, hostname, is_core, str(switch_id),
            )

    async def check_switch_duplicate(self, ip: str, hostname: str | None, exclude_id=None) -> str | None:
        async with self._pool.acquire() as conn:
            q_ip = "SELECT id FROM switches WHERE ip_address = $1 AND enabled = true"
            args_ip = [ip]
            if exclude_id:
                q_ip += " AND id != $2"
                args_ip.append(str(exclude_id))
            if await conn.fetchrow(q_ip, *args_ip):
                return f"IP address {ip} is already used by another switch."
            if hostname:
                q_hn = "SELECT id FROM switches WHERE hostname = $1 AND enabled = true"
                args_hn = [hostname]
                if exclude_id:
                    q_hn += " AND id != $2"
                    args_hn.append(str(exclude_id))
                if await conn.fetchrow(q_hn, *args_hn):
                    return f"Hostname '{hostname}' is already used by another switch."
        return None

    # ------------------------------------------------------------------
    # ARP core (Process 1)
    # ------------------------------------------------------------------

    async def upsert_arp(self, entries: list[ArpEntry]) -> tuple[int, int]:
        """Upsert ARP entries. Returns (changed, gone) counts.

        changed — new MACs inserted + existing MACs whose topology changed.
        gone    — always 0 (ARP table has no gone detection).
        """
        if not entries:
            return 0, 0
        changed = 0
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                for entry in entries:
                    new_hash = _topology_hash(
                        entry.ip_addresses, entry.vlan_ids, entry.interfaces
                    )
                    row = await conn.fetchrow(
                        "SELECT topology_hash, ip_addresses, vlan_ids, interfaces "
                        "FROM arp_core WHERE mac_address = $1",
                        entry.mac_address,
                    )

                    if row is None:
                        # New MAC
                        changed += 1
                        await conn.execute(
                            """INSERT INTO arp_core
                               (id, mac_address, ip_addresses, vlan_ids, interfaces, topology_hash)
                               VALUES ($1, $2, $3, $4, $5, $6)""",
                            _uuid7(),
                            entry.mac_address,
                            entry.ip_addresses,
                            entry.vlan_ids,
                            entry.interfaces,
                            new_hash,
                        )
                    elif row["topology_hash"] != new_hash:
                        # Changed — log and update
                        changed += 1
                        flags = 0
                        if _to_str_list(entry.ip_addresses) != _to_str_list(row["ip_addresses"]):
                            flags |= FLAG_IP
                        if _to_str_list(entry.vlan_ids) != _to_str_list(row["vlan_ids"]):
                            flags |= FLAG_VLAN
                        if _to_str_list(entry.interfaces) != _to_str_list(row["interfaces"]):
                            flags |= FLAG_IFACE

                        await conn.execute(
                            """INSERT INTO arp_changes
                               (id, mac_address, ip_addresses, vlan_ids, interfaces, change_flags)
                               VALUES ($1, $2, $3, $4, $5, $6)""",
                            _uuid7(),
                            entry.mac_address,
                            entry.ip_addresses,
                            entry.vlan_ids,
                            entry.interfaces,
                            flags,
                        )
                        await conn.execute(
                            """UPDATE arp_core SET
                               ip_addresses = $2, vlan_ids = $3, interfaces = $4,
                               topology_hash = $5, last_seen = now(), poll_count = poll_count + 1
                               WHERE mac_address = $1""",
                            entry.mac_address,
                            entry.ip_addresses,
                            entry.vlan_ids,
                            entry.interfaces,
                            new_hash,
                        )
                    else:
                        # No change — bump last_seen
                        await conn.execute(
                            """UPDATE arp_core SET last_seen = now(), poll_count = poll_count + 1
                               WHERE mac_address = $1""",
                            entry.mac_address,
                        )
        return changed, 0

    # ------------------------------------------------------------------
    # MAC current (Process 2)
    # ------------------------------------------------------------------

    async def upsert_macs(self, entries: list[MacEntry], switch_ip: str | None = None) -> tuple[int, int]:
        """Upsert FDB entries and detect disappeared MACs.

        switch_ip must be provided to enable disappearance detection.
        MACs previously seen on switch_ip but absent from entries are recorded
        in mac_changes with FLAG_GONE=0 and removed from mac_current.

        Returns (changed, gone) counts:
          changed — new MACs inserted + existing MACs whose topology changed.
          gone    — MACs that disappeared from this switch since last poll.
        """
        if not entries and not switch_ip:
            return 0, 0
        changed = 0
        gone = 0
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                # --- disappearance detection ---
                if switch_ip:
                    prev_rows = await conn.fetch(
                        "SELECT mac_address, switch_ips, vlan_ids, interfaces "
                        "FROM mac_current WHERE $1::inet = ANY(switch_ips)",
                        switch_ip,
                    )
                    prev_macs = {str(r["mac_address"]): r for r in prev_rows}
                    new_macs = {e.mac_address.lower() for e in entries}

                    for mac, row in prev_macs.items():
                        if mac.lower() in new_macs:
                            continue
                        # Record disappearance with last-known state
                        gone += 1
                        await conn.execute(
                            """INSERT INTO mac_changes
                               (id, mac_address, switch_ips, vlan_ids, interfaces, change_flags)
                               VALUES ($1, $2, $3, $4, $5, $6)""",
                            _uuid7(),
                            mac,
                            list(row["switch_ips"]),
                            list(row["vlan_ids"]),
                            list(row["interfaces"]),
                            FLAG_GONE,
                        )
                        remaining_ips = [ip for ip in row["switch_ips"] if str(ip) != switch_ip]
                        if remaining_ips:
                            new_hash = _topology_hash(
                                remaining_ips, row["vlan_ids"], row["interfaces"]
                            )
                            await conn.execute(
                                """UPDATE mac_current SET switch_ips=$2, topology_hash=$3,
                                   last_seen=now() WHERE mac_address=$1""",
                                mac, remaining_ips, new_hash,
                            )
                        else:
                            await conn.execute(
                                "DELETE FROM mac_current WHERE mac_address=$1", mac
                            )

                # --- upsert new/changed entries ---
                for entry in entries:
                    new_hash = _topology_hash(
                        entry.switch_ips, entry.vlan_ids, entry.interfaces
                    )
                    row = await conn.fetchrow(
                        "SELECT topology_hash, switch_ips, vlan_ids, interfaces "
                        "FROM mac_current WHERE mac_address = $1",
                        entry.mac_address,
                    )

                    if row is None:
                        changed += 1
                        await conn.execute(
                            """INSERT INTO mac_current
                               (id, mac_address, switch_ips, vlan_ids, interfaces, topology_hash)
                               VALUES ($1, $2, $3, $4, $5, $6)""",
                            _uuid7(),
                            entry.mac_address,
                            entry.switch_ips,
                            entry.vlan_ids,
                            entry.interfaces,
                            new_hash,
                        )
                    elif row["topology_hash"] != new_hash:
                        changed += 1
                        flags = 0
                        if _to_str_list(entry.switch_ips) != _to_str_list(row["switch_ips"]):
                            flags |= FLAG_IP
                        if _to_str_list(entry.vlan_ids) != _to_str_list(row["vlan_ids"]):
                            flags |= FLAG_VLAN
                        if _to_str_list(entry.interfaces) != _to_str_list(row["interfaces"]):
                            flags |= FLAG_IFACE

                        await conn.execute(
                            """INSERT INTO mac_changes
                               (id, mac_address, switch_ips, vlan_ids, interfaces, change_flags)
                               VALUES ($1, $2, $3, $4, $5, $6)""",
                            _uuid7(),
                            entry.mac_address,
                            entry.switch_ips,
                            entry.vlan_ids,
                            entry.interfaces,
                            flags,
                        )
                        await conn.execute(
                            """UPDATE mac_current SET
                               switch_ips = $2, vlan_ids = $3, interfaces = $4,
                               topology_hash = $5, last_seen = now(), poll_count = poll_count + 1
                               WHERE mac_address = $1""",
                            entry.mac_address,
                            entry.switch_ips,
                            entry.vlan_ids,
                            entry.interfaces,
                            new_hash,
                        )
                    else:
                        await conn.execute(
                            """UPDATE mac_current SET last_seen = now(), poll_count = poll_count + 1
                               WHERE mac_address = $1""",
                            entry.mac_address,
                        )
        return changed, gone

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    async def get_user_by_email(self, email: str) -> asyncpg.Record | None:
        async with self._pool.acquire() as conn:
            return await conn.fetchrow(
                "SELECT * FROM users WHERE email = $1", email
            )

    async def get_user_by_id(self, user_id) -> asyncpg.Record | None:
        async with self._pool.acquire() as conn:
            return await conn.fetchrow(
                "SELECT * FROM users WHERE id = $1", str(user_id)
            )

    async def get_users(self) -> list[asyncpg.Record]:
        """Return all users without password_hash."""
        async with self._pool.acquire() as conn:
            return await conn.fetch(
                "SELECT id, email, role, enabled, created_at FROM users ORDER BY created_at"
            )

    async def create_user(self, email: str, password_hash: str, role: str) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO users (id, email, password_hash, role)
                   VALUES ($1, $2, $3, $4)""",
                _uuid7(), email, password_hash, role,
            )

    async def update_password(self, user_id, password_hash: str) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE users SET password_hash = $1 WHERE id = $2",
                password_hash, str(user_id),
            )

    async def disable_user(self, user_id) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE users SET enabled = false WHERE id = $1", str(user_id)
            )

    async def set_user_role(self, user_id, role: str) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE users SET role = $1 WHERE id = $2", role, str(user_id)
            )

    async def enable_user(self, user_id) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE users SET enabled = true WHERE id = $1", str(user_id)
            )

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    async def log_action(
        self,
        user_id,
        action: str,
        detail: dict,
        ip_address: str,
    ) -> None:
        """Always uses a separate transaction — audit errors never roll back business ops."""
        async with self._pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO audit_log (id, user_id, action, detail, ip_address)
                   VALUES ($1, $2, $3, $4, $5)""",
                _uuid7(),
                str(user_id) if user_id is not None else None,
                action,
                json.dumps(detail),
                ip_address,
            )

    async def get_audit_log(
        self,
        *,
        user_id=None,
        action: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        search: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[asyncpg.Record]:
        conditions = []
        args: list = []
        idx = 1

        if user_id is not None:
            conditions.append(f"al.user_id = ${idx}")
            args.append(str(user_id))
            idx += 1
        if action is not None:
            conditions.append(f"al.action = ${idx}")
            args.append(action)
            idx += 1
        if since is not None:
            conditions.append(f"al.logged_at >= ${idx}")
            args.append(since)
            idx += 1
        if until is not None:
            conditions.append(f"al.logged_at <= ${idx}")
            args.append(until)
            idx += 1
        if search is not None:
            conditions.append(
                f"(al.action ILIKE ${idx}"
                f" OR u.email ILIKE ${idx}"
                f" OR al.ip_address::text ILIKE ${idx}"
                f" OR al.detail::text ILIKE ${idx}"
                f" OR al.logged_at::text ILIKE ${idx})"
            )
            args.append(f"%{search}%")
            idx += 1

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        sql = f"""
            SELECT al.id, al.user_id, u.email AS user_email,
                   al.action, al.detail, al.ip_address, al.logged_at
            FROM audit_log al
            LEFT JOIN users u ON u.id = al.user_id
            {where}
            ORDER BY al.logged_at DESC
            LIMIT ${idx} OFFSET ${idx + 1}
        """
        args.extend([limit, offset])

        async with self._pool.acquire() as conn:
            return await conn.fetch(sql, *args)

    # ------------------------------------------------------------------
    # Search helpers (used by web.py)
    # ------------------------------------------------------------------

    async def get_macs_by_switch(self, switch_ip: str) -> list[asyncpg.Record]:
        """Return mac_current rows whose switch_ips array contains switch_ip."""
        async with self._pool.acquire() as conn:
            return await conn.fetch(
                "SELECT mac_address, switch_ips, vlan_ids, interfaces, last_seen "
                "FROM mac_current "
                "WHERE $1::inet = ANY(switch_ips) "
                "ORDER BY mac_address",
                switch_ip,
            )

    async def search_by_mac(self, mac: str) -> list[asyncpg.Record]:
        """Search arp_core + mac_current by MAC address (partial match)."""
        async with self._pool.acquire() as conn:
            arp = await conn.fetch(
                "SELECT mac_address, ip_addresses, vlan_ids, interfaces, last_seen "
                "FROM arp_core WHERE mac_address::text ILIKE $1",
                f"%{mac}%",
            )
            mac_cur = await conn.fetch(
                "SELECT mac_address, switch_ips, vlan_ids, interfaces, last_seen "
                "FROM mac_current WHERE mac_address::text ILIKE $1",
                f"%{mac}%",
            )
        return list(arp) + list(mac_cur)

    async def search_by_ip(self, ip: str) -> list[asyncpg.Record]:
        """Search arp_core by IP address (text match in array)."""
        async with self._pool.acquire() as conn:
            return await conn.fetch(
                "SELECT mac_address, ip_addresses, vlan_ids, interfaces, last_seen "
                "FROM arp_core WHERE EXISTS ("
                "  SELECT 1 FROM unnest(ip_addresses) AS a WHERE a::text ILIKE $1"
                ")",
                f"%{ip}%",
            )

    async def get_history(
        self,
        mac: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[asyncpg.Record]:
        """Return combined arp_changes + mac_changes ordered by time."""
        conditions = []
        args: list = []
        idx = 1

        if mac:
            conditions.append(f"mac_address::text ILIKE ${idx}")
            args.append(f"%{mac}%")
            idx += 1

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        sql = f"""
            SELECT mac_address, 'arp' AS source, change_flags, changed_at,
                   ip_addresses, vlan_ids, interfaces
            FROM arp_changes {where}
            UNION ALL
            SELECT mac_address, 'mac' AS source, change_flags, changed_at,
                   switch_ips AS ip_addresses, vlan_ids, interfaces
            FROM mac_changes {where}
            ORDER BY changed_at DESC
            LIMIT ${idx} OFFSET ${idx + 1}
        """
        args.extend([limit, offset])
        async with self._pool.acquire() as conn:
            return await conn.fetch(sql, *args)

    async def delete_switch(self, switch_id) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE switches SET enabled = false WHERE id = $1", str(switch_id)
            )

    async def get_disabled_switches(self) -> list[asyncpg.Record]:
        async with self._pool.acquire() as conn:
            return await conn.fetch(
                "SELECT * FROM switches WHERE enabled = false ORDER BY ip_address"
            )

    async def enable_switch(self, switch_id) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE switches SET enabled = true WHERE id = $1", str(switch_id)
            )

    async def update_switch_hostname_by_ip(self, ip: str, hostname: str) -> None:
        """Update the hostname of an enabled switch identified by its IP address."""
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE switches SET hostname = $1 WHERE ip_address = $2 AND enabled = true",
                hostname, ip,
            )

    # ------------------------------------------------------------------
    # Collection log
    # ------------------------------------------------------------------

    async def get_collection_log(
        self,
        *,
        collector: str | None = None,
        switch_ip: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        errors_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[asyncpg.Record]:
        conditions: list[str] = []
        args: list = []
        idx = 1

        if collector:
            conditions.append(f"collector = ${idx}")
            args.append(collector)
            idx += 1
        if switch_ip:
            conditions.append(f"switch_ip::text ILIKE ${idx}")
            args.append(f"%{switch_ip}%")
            idx += 1
        if since is not None:
            conditions.append(f"polled_at >= ${idx}")
            args.append(since)
            idx += 1
        if until is not None:
            conditions.append(f"polled_at <= ${idx}")
            args.append(until)
            idx += 1
        if errors_only:
            conditions.append("error IS NOT NULL")

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        sql = f"""
            SELECT id, polled_at, collector, switch_ip,
                   duration_ms, macs_total, macs_changed, macs_gone, error
            FROM collection_log
            {where}
            ORDER BY polled_at DESC
            LIMIT ${idx} OFFSET ${idx + 1}
        """
        args.extend([limit, offset])
        async with self._pool.acquire() as conn:
            return await conn.fetch(sql, *args)

    async def log_collection(
        self,
        *,
        collector: str,
        switch_ip: str,
        duration_ms: int,
        macs_total: int | None = None,
        macs_changed: int = 0,
        macs_gone: int = 0,
        error: str | None = None,
    ) -> None:
        """Write one row to collection_log. Always uses a separate connection
        so a DB error here never rolls back the collector's own transaction."""
        async with self._pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO collection_log
                   (id, collector, switch_ip, duration_ms,
                    macs_total, macs_changed, macs_gone, error)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8)""",
                _uuid7(), collector, switch_ip, duration_ms,
                macs_total, macs_changed, macs_gone, error,
            )
