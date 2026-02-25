"""Tests for the Database layer. Requires a running PostgreSQL with schema applied.

Run:
    export $(cat .env | xargs) && python -m pytest tests/test_db.py -v
"""

import asyncio
import os
import sys

import pytest
import pytest_asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from db import (
    ArpEntry,
    Database,
    MacEntry,
    FLAG_IFACE,
    FLAG_IP,
    FLAG_VLAN,
    _topology_hash,
)


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

@pytest_asyncio.fixture
async def db():
    database = Database()
    await database.connect()
    await database.ensure_partitions(4)
    yield database
    # Cleanup test data
    async with database._pool.acquire() as conn:
        await conn.execute("DELETE FROM arp_changes")
        await conn.execute("DELETE FROM mac_changes")
        await conn.execute("DELETE FROM arp_core")
        await conn.execute("DELETE FROM mac_current")
        await conn.execute(
            "DELETE FROM switches WHERE ip_address NOT IN ('192.168.1.1'::inet)"
        )
    await database.close()


# ------------------------------------------------------------------
# topology_hash
# ------------------------------------------------------------------

class TestTopologyHash:
    def test_same_arrays_same_hash(self):
        h1 = _topology_hash(["10.0.0.1"], [100], ["Gi0/1"])
        h2 = _topology_hash(["10.0.0.1"], [100], ["Gi0/1"])
        assert h1 == h2

    def test_different_order_same_hash(self):
        h1 = _topology_hash(["10.0.0.2", "10.0.0.1"], [200, 100], ["Gi0/2", "Gi0/1"])
        h2 = _topology_hash(["10.0.0.1", "10.0.0.2"], [100, 200], ["Gi0/1", "Gi0/2"])
        assert h1 == h2

    def test_different_values_different_hash(self):
        h1 = _topology_hash(["10.0.0.1"], [100], ["Gi0/1"])
        h2 = _topology_hash(["10.0.0.2"], [100], ["Gi0/1"])
        assert h1 != h2

    def test_empty_arrays(self):
        h = _topology_hash([], [], [])
        assert isinstance(h, str)
        assert len(h) == 32  # MD5 hex


# ------------------------------------------------------------------
# Switches
# ------------------------------------------------------------------

class TestSwitches:
    @pytest.mark.asyncio
    async def test_add_switch(self, db):
        await db.add_switch("10.99.99.1", "test-switch", False)
        rows = await db.get_switches()
        ips = [str(r["ip_address"]) for r in rows]
        assert "10.99.99.1" in ips

    @pytest.mark.asyncio
    async def test_add_switch_duplicate(self, db):
        await db.add_switch("10.99.99.2", "test-sw-2", False)
        await db.add_switch("10.99.99.2", "test-sw-2-dup", False)  # should not fail
        rows = await db.get_switches()
        matches = [r for r in rows if str(r["ip_address"]) == "10.99.99.2"]
        assert len(matches) == 1
        assert matches[0]["hostname"] == "test-sw-2"  # original kept

    @pytest.mark.asyncio
    async def test_get_switches_filter_core(self, db):
        await db.add_switch("10.99.99.3", "core-test", True)
        await db.add_switch("10.99.99.4", "access-test", False)
        core = await db.get_switches(is_core=True)
        access = await db.get_switches(is_core=False)
        core_ips = [str(r["ip_address"]) for r in core]
        access_ips = [str(r["ip_address"]) for r in access]
        assert "10.99.99.3" in core_ips
        assert "10.99.99.4" in access_ips
        assert "10.99.99.3" not in access_ips


# ------------------------------------------------------------------
# ARP upsert (Process 1)
# ------------------------------------------------------------------

class TestArpUpsert:
    @pytest.mark.asyncio
    async def test_insert_new(self, db):
        entry = ArpEntry(
            mac_address="AA:BB:CC:DD:EE:01",
            ip_addresses=["10.0.0.1"],
            vlan_ids=[100],
            interfaces=["Vlan100"],
        )
        await db.upsert_arp([entry])

        async with db._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM arp_core WHERE mac_address = $1", "AA:BB:CC:DD:EE:01"
            )
        assert row is not None
        assert row["poll_count"] == 1
        assert [str(x) for x in row["ip_addresses"]] == ["10.0.0.1"]

    @pytest.mark.asyncio
    async def test_no_change_bumps_poll_count(self, db):
        entry = ArpEntry("AA:BB:CC:DD:EE:02", ["10.0.0.2"], [200], ["Vlan200"])
        await db.upsert_arp([entry])
        await db.upsert_arp([entry])
        await db.upsert_arp([entry])

        async with db._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT poll_count FROM arp_core WHERE mac_address = $1",
                "AA:BB:CC:DD:EE:02",
            )
        assert row["poll_count"] == 3

    @pytest.mark.asyncio
    async def test_change_ip_logs_change(self, db):
        entry1 = ArpEntry("AA:BB:CC:DD:EE:03", ["10.0.0.3"], [100], ["Vlan100"])
        await db.upsert_arp([entry1])

        entry2 = ArpEntry("AA:BB:CC:DD:EE:03", ["10.0.0.99"], [100], ["Vlan100"])
        await db.upsert_arp([entry2])

        async with db._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM arp_core WHERE mac_address = $1", "AA:BB:CC:DD:EE:03"
            )
            change = await conn.fetchrow(
                "SELECT * FROM arp_changes WHERE mac_address = $1",
                "AA:BB:CC:DD:EE:03",
            )
        assert [str(x) for x in row["ip_addresses"]] == ["10.0.0.99"]
        assert row["poll_count"] == 2
        assert change is not None
        assert change["change_flags"] == FLAG_IP  # only IP changed

    @pytest.mark.asyncio
    async def test_change_vlan_and_interface(self, db):
        entry1 = ArpEntry("AA:BB:CC:DD:EE:04", ["10.0.0.4"], [100], ["Vlan100"])
        await db.upsert_arp([entry1])

        entry2 = ArpEntry("AA:BB:CC:DD:EE:04", ["10.0.0.4"], [200], ["Vlan200"])
        await db.upsert_arp([entry2])

        async with db._pool.acquire() as conn:
            change = await conn.fetchrow(
                "SELECT change_flags FROM arp_changes WHERE mac_address = $1",
                "AA:BB:CC:DD:EE:04",
            )
        assert change["change_flags"] == FLAG_VLAN | FLAG_IFACE  # 3

    @pytest.mark.asyncio
    async def test_change_everything(self, db):
        entry1 = ArpEntry("AA:BB:CC:DD:EE:05", ["10.0.0.5"], [100], ["Vlan100"])
        await db.upsert_arp([entry1])

        entry2 = ArpEntry("AA:BB:CC:DD:EE:05", ["10.0.0.99"], [200], ["Vlan200"])
        await db.upsert_arp([entry2])

        async with db._pool.acquire() as conn:
            change = await conn.fetchrow(
                "SELECT change_flags FROM arp_changes WHERE mac_address = $1",
                "AA:BB:CC:DD:EE:05",
            )
        assert change["change_flags"] == FLAG_IP | FLAG_VLAN | FLAG_IFACE  # 7

    @pytest.mark.asyncio
    async def test_empty_entries(self, db):
        await db.upsert_arp([])  # should not raise


# ------------------------------------------------------------------
# MAC upsert (Process 2)
# ------------------------------------------------------------------

class TestMacUpsert:
    @pytest.mark.asyncio
    async def test_insert_new(self, db):
        entry = MacEntry(
            mac_address="11:22:33:44:55:01",
            switch_ips=["192.168.1.15"],
            vlan_ids=[323],
            interfaces=["Gi1/0/5"],
        )
        await db.upsert_macs([entry])

        async with db._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM mac_current WHERE mac_address = $1",
                "11:22:33:44:55:01",
            )
        assert row is not None
        assert row["poll_count"] == 1
        assert [str(x) for x in row["switch_ips"]] == ["192.168.1.15"]

    @pytest.mark.asyncio
    async def test_no_change_bumps_poll_count(self, db):
        entry = MacEntry("11:22:33:44:55:02", ["192.168.1.15"], [100], ["Gi1/0/1"])
        await db.upsert_macs([entry])
        await db.upsert_macs([entry])

        async with db._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT poll_count FROM mac_current WHERE mac_address = $1",
                "11:22:33:44:55:02",
            )
        assert row["poll_count"] == 2

    @pytest.mark.asyncio
    async def test_change_switch_ip(self, db):
        entry1 = MacEntry("11:22:33:44:55:03", ["192.168.1.15"], [100], ["Gi1/0/1"])
        await db.upsert_macs([entry1])

        entry2 = MacEntry("11:22:33:44:55:03", ["192.168.1.200"], [100], ["Gi1/0/1"])
        await db.upsert_macs([entry2])

        async with db._pool.acquire() as conn:
            change = await conn.fetchrow(
                "SELECT change_flags FROM mac_changes WHERE mac_address = $1",
                "11:22:33:44:55:03",
            )
        assert change["change_flags"] == FLAG_IP

    @pytest.mark.asyncio
    async def test_loop_multiple_switches(self, db):
        """Simulate a loop: MAC appears on two switches."""
        entry1 = MacEntry("11:22:33:44:55:04", ["192.168.1.15"], [100], ["Gi1/0/1"])
        await db.upsert_macs([entry1])

        entry2 = MacEntry(
            "11:22:33:44:55:04",
            ["192.168.1.15", "192.168.1.200"],
            [100, 200],
            ["Gi1/0/1", "Gi2/0/10"],
        )
        await db.upsert_macs([entry2])

        async with db._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM mac_current WHERE mac_address = $1",
                "11:22:33:44:55:04",
            )
            change = await conn.fetchrow(
                "SELECT change_flags FROM mac_changes WHERE mac_address = $1",
                "11:22:33:44:55:04",
            )
        assert len(list(row["switch_ips"])) == 2
        assert len(list(row["vlan_ids"])) == 2
        assert change["change_flags"] == FLAG_IP | FLAG_VLAN | FLAG_IFACE  # 7

    @pytest.mark.asyncio
    async def test_multiple_changes_tracked(self, db):
        """Multiple sequential changes create multiple change log entries."""
        e1 = MacEntry("11:22:33:44:55:05", ["192.168.1.15"], [100], ["Gi1/0/1"])
        e2 = MacEntry("11:22:33:44:55:05", ["192.168.1.15"], [200], ["Gi1/0/1"])
        e3 = MacEntry("11:22:33:44:55:05", ["192.168.1.15"], [200], ["Gi1/0/2"])

        await db.upsert_macs([e1])
        await asyncio.sleep(0.01)  # ensure different changed_at for UNIQUE
        await db.upsert_macs([e2])
        await asyncio.sleep(0.01)
        await db.upsert_macs([e3])

        async with db._pool.acquire() as conn:
            changes = await conn.fetch(
                "SELECT change_flags FROM mac_changes WHERE mac_address = $1 "
                "ORDER BY changed_at",
                "11:22:33:44:55:05",
            )
        assert len(changes) == 2
        assert changes[0]["change_flags"] == FLAG_VLAN      # 2
        assert changes[1]["change_flags"] == FLAG_IFACE      # 1

    @pytest.mark.asyncio
    async def test_empty_entries(self, db):
        await db.upsert_macs([])  # should not raise


# ------------------------------------------------------------------
# Partitions
# ------------------------------------------------------------------

class TestPartitions:
    @pytest.mark.asyncio
    async def test_ensure_partitions(self, db):
        created = await db._pool.fetchval(
            "SELECT create_weekly_partitions('arp_changes', 2)"
        )
        assert created >= 0  # 0 if already exist, >0 if new

    @pytest.mark.asyncio
    async def test_partitions_exist(self, db):
        async with db._pool.acquire() as conn:
            arp_parts = await conn.fetch(
                "SELECT tablename FROM pg_tables WHERE tablename LIKE 'arp_changes_%'"
            )
            mac_parts = await conn.fetch(
                "SELECT tablename FROM pg_tables WHERE tablename LIKE 'mac_changes_%'"
            )
        assert len(arp_parts) >= 1
        assert len(mac_parts) >= 1
