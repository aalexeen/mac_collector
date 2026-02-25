"""FDB (MAC address table) collector for Cisco access switches via SNMP.

Polls BRIDGE-MIB per-VLAN (community@vlan indexing) and filters out trunk
ports.  Returns a list of MacEntry objects ready for Database.upsert_macs().

Run standalone (reads access switch IPs from DB, writes results back):

    python fdb_collector.py
    python fdb_collector.py --dry-run           # print entries, no DB write
    python fdb_collector.py --ip 192.168.1.200 # override IP from DB

One MacEntry per unique MAC address across all VLANs on a given switch.
Multiple switch IPs, VLANs, and interfaces are aggregated into sorted lists —
this handles network loops without data loss.

Only MAC addresses learned on ACCESS ports are collected; trunk port MACs
(uplinks, inter-switch traffic) are filtered out automatically.
"""

import asyncio
import os
import subprocess
from collections import defaultdict

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from db import MacEntry


class FdbCollector:
    """Collect FDB table from a Cisco access switch via SNMP.

    Usage::

        collector = FdbCollector("192.168.1.200")
        entries = collector.collect()           # synchronous
        entries = await collector.collect_async()   # async (runs in thread)
    """

    OID_VTP_VLAN    = ".1.3.6.1.4.1.9.9.46.1.3.1.1.2"    # vtpVlanState
    OID_FDB_MAC     = ".1.3.6.1.2.1.17.4.3.1.1"           # dot1dTpFdbAddress
    OID_FDB_PORT    = ".1.3.6.1.2.1.17.4.3.1.2"           # dot1dTpFdbPort
    OID_BRIDGE_IF   = ".1.3.6.1.2.1.17.1.4.1.2"           # dot1dBasePortIfIndex
    OID_IF_NAME     = ".1.3.6.1.2.1.31.1.1.1.1"           # ifName
    OID_TRUNK_STATE  = ".1.3.6.1.4.1.9.9.46.1.6.1.1.13"   # vlanTrunkPortDynamicState
    OID_TRUNK_STATUS = ".1.3.6.1.4.1.9.9.46.1.6.1.1.14"   # vlanTrunkPortDynamicStatus

    # vtpVlanState value for active VLAN
    _VLAN_ACTIVE = 1

    # Cisco VTP VLAN IDs reserved for internal use — always skip
    _VLAN_RESERVED = range(1002, 1006)  # 1002–1005 inclusive

    def __init__(self, ip: str, community: str | None = None, timeout: int = 30):
        """
        Args:
            ip:        Switch management IP address.
            community: SNMP v2c community string.  Falls back to the
                       SNMP_COMMUNITY environment variable.
            timeout:   Per-snmpwalk subprocess timeout in seconds.
        """
        self.ip = ip
        self.community = community or os.environ.get("SNMP_COMMUNITY", "")
        self.timeout = timeout

    # ------------------------------------------------------------------
    # SNMP transport
    # ------------------------------------------------------------------

    def _snmpwalk(self, oid: str, vlan: int | None = None) -> list[str]:
        """Run snmpwalk and return non-empty output lines.

        When *vlan* is provided the community string is formatted as
        ``community@vlan`` — the Cisco per-VLAN BRIDGE-MIB indexing trick.

        Raises:
            FileNotFoundError:        snmpwalk binary not found.
            subprocess.TimeoutExpired: switch unreachable or slow.
        """
        community = f"{self.community}@{vlan}" if vlan is not None else self.community
        result = subprocess.run(
            ["snmpwalk", "-v2c", "-c", community, self.ip, oid],
            capture_output=True,
            text=True,
            timeout=self.timeout,
        )
        if not result.stdout.strip():
            return []
        return result.stdout.strip().split("\n")

    # ------------------------------------------------------------------
    # Parsers
    # ------------------------------------------------------------------

    def _parse_vlans(self, lines: list[str]) -> list[int]:
        """Parse vtpVlanState output — return active, non-reserved VLAN IDs.

        OID suffix is the VLAN ID; value 1 = active.

        Returns:
            Sorted list of active VLAN IDs excluding reserved range 1002–1005.
        """
        vlans: list[int] = []
        for line in lines:
            try:
                oid_part, value_part = line.split(" = INTEGER: ", 1)
                vlan_id = int(oid_part.split(".")[-1])
                if int(value_part.strip()) == self._VLAN_ACTIVE and vlan_id not in self._VLAN_RESERVED:
                    vlans.append(vlan_id)
            except (ValueError, IndexError):
                continue
        return sorted(vlans)

    def _parse_int_map(self, lines: list[str]) -> dict[int, int]:
        """Parse generic INTEGER OID where both key and value are integers.

        Used for: dot1dBasePortIfIndex,
                  vlanTrunkPortDynamicState, vlanTrunkPortDynamicStatus.

        Returns:
            Mapping of last OID component (int) → INTEGER value.
        """
        mapping: dict[int, int] = {}
        for line in lines:
            try:
                oid_part, value_part = line.split(" = INTEGER: ", 1)
                key = int(oid_part.split(".")[-1])
                mapping[key] = int(value_part.strip())
            except (ValueError, IndexError):
                continue
        return mapping

    def _parse_fdb_ports(self, lines: list[str]) -> dict[str, int]:
        """Parse dot1dTpFdbPort output.

        OID suffix is the MAC address as 6 decimal octets (same as
        dot1dTpFdbAddress), so we use the full 6-component suffix as key.

        Returns:
            Mapping of oid_suffix (e.g. ``"124.77.143.11.142.57"``) → bridge port number.
        """
        mapping: dict[str, int] = {}
        for line in lines:
            try:
                oid_part, value_part = line.split(" = INTEGER: ", 1)
                suffix = ".".join(oid_part.split(".")[-6:])
                mapping[suffix] = int(value_part.strip())
            except (ValueError, IndexError):
                continue
        return mapping

    def _parse_fdb_macs(self, lines: list[str]) -> list[tuple[str, str]]:
        """Parse dot1dTpFdbAddress output.

        OID suffix is the MAC address encoded as 6 decimal octets, e.g.:
          ...17.4.3.1.1.124.77.143.11.142.57 = Hex-STRING: 7C 4D 8F 0B 8E 39

        The same 6-octet suffix is used as the index in dot1dTpFdbPort, so
        we use the full suffix string as the join key.

        Returns:
            List of (oid_suffix, mac_address) where oid_suffix is the last
            6 dot-separated decimal components, e.g. ``"124.77.143.11.142.57"``.
        """
        result: list[tuple[str, str]] = []
        for line in lines:
            try:
                oid_part, value_part = line.split(" = Hex-STRING: ", 1)
                suffix = ".".join(oid_part.split(".")[-6:])
                mac = ":".join(b.upper() for b in value_part.strip().split())
                result.append((suffix, mac))
            except (ValueError, IndexError):
                continue
        return result

    def _parse_if_names(self, lines: list[str]) -> dict[int, str]:
        """Parse ifName output.

        Returns:
            Mapping of ifindex → interface name string (e.g. ``"Gi1/0/1"``).
        """
        mapping: dict[int, str] = {}
        for line in lines:
            try:
                oid_part, value_part = line.split(" = STRING: ", 1)
                idx = int(oid_part.split(".")[-1])
                mapping[idx] = value_part.strip().strip('"')
            except (ValueError, IndexError):
                continue
        return mapping

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_access_ifindexes(self) -> set[int]:
        """Return the set of ifIndex values that correspond to ACCESS ports.

        Classification uses Cisco VTP MIB trunk state/status OIDs:

        +---------------------------------+--------------------+--------+
        | vlanTrunkPortDynamicState       | DynamicStatus      | Result |
        +=================================+====================+========+
        | on(1) / nonegotiate(5)          | any                | TRUNK  |
        | off(2)                          | any                | ACCESS |
        | desirable(3) / auto(4)          | trunking(1)        | TRUNK  |
        | desirable(3) / auto(4)          | notTrunking(2)     | ACCESS |
        +---------------------------------+--------------------+--------+
        """
        states   = self._parse_int_map(self._snmpwalk(self.OID_TRUNK_STATE))
        statuses = self._parse_int_map(self._snmpwalk(self.OID_TRUNK_STATUS))

        access: set[int] = set()
        for ifidx, state_val in states.items():
            status_val = statuses.get(ifidx, 0)
            if state_val in (1, 5):        # on / nonegotiate → trunk
                continue
            elif state_val == 2:           # off → access
                access.add(ifidx)
            elif status_val == 1:          # desirable/auto + trunking
                continue
            else:                          # desirable/auto + not trunking
                access.add(ifidx)
        return access

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def collect(self) -> list[MacEntry]:
        """Poll the switch FDB table and return one MacEntry per unique MAC.

        Steps:
          1. Discover active VLANs via vtpVlanState.
          2. Identify ACCESS port ifIndexes via trunk state/status OIDs.
          3. For each VLAN walk dot1dTpFdbAddress and dot1dTpFdbPort using
             the ``community@vlan`` indexing scheme.
          4. Resolve bridge-port → ifIndex via dot1dBasePortIfIndex.
          5. Filter out MACs on trunk ports.
          6. Aggregate all VLANs/interfaces per MAC into sorted lists.

        Returns:
            list[MacEntry] — one entry per unique MAC, fields sorted.

        Raises:
            FileNotFoundError:        snmpwalk binary not found.
            subprocess.TimeoutExpired: switch unreachable or slow.
        """
        ifnames       = self._parse_if_names(self._snmpwalk(self.OID_IF_NAME))
        access_ports  = self._get_access_ifindexes()
        vlans         = self._parse_vlans(self._snmpwalk(self.OID_VTP_VLAN))

        # Aggregate per MAC address.
        # A single MAC may be learned on multiple VLANs/interfaces (loop /
        # multi-homing) → collect all switch IPs, VLANs, and interface names.
        by_mac: dict[str, dict[str, set]] = defaultdict(
            lambda: {"switch_ips": set(), "vlan_ids": set(), "interfaces": set()}
        )

        for vlan in vlans:
            fdb_macs  = self._parse_fdb_macs( self._snmpwalk(self.OID_FDB_MAC,  vlan))
            fdb_ports = self._parse_fdb_ports(self._snmpwalk(self.OID_FDB_PORT, vlan))
            bp_map    = self._parse_int_map(  self._snmpwalk(self.OID_BRIDGE_IF, vlan))

            for suffix, mac in fdb_macs:
                bridge_port = fdb_ports.get(suffix)
                if bridge_port is None:
                    continue
                ifidx = bp_map.get(bridge_port)
                if ifidx is None or ifidx not in access_ports:
                    continue

                ifname = ifnames.get(ifidx, f"ifindex-{ifidx}")
                by_mac[mac]["switch_ips"].add(self.ip)
                by_mac[mac]["vlan_ids"].add(vlan)
                by_mac[mac]["interfaces"].add(ifname)

        return [
            MacEntry(
                mac_address=mac,
                switch_ips=sorted(data["switch_ips"]),
                vlan_ids=sorted(data["vlan_ids"]),
                interfaces=sorted(data["interfaces"]),
            )
            for mac, data in by_mac.items()
        ]

    async def collect_async(self) -> list[MacEntry]:
        """Async wrapper: runs collect() in a thread-pool executor.

        Use this from async code to avoid blocking the event loop::

            entries = await collector.collect_async()
            await db.upsert_macs(entries)
        """
        return await asyncio.to_thread(self.collect)


# ------------------------------------------------------------------
# CLI entry point
# ------------------------------------------------------------------

async def _main():
    import argparse
    from db import Database

    parser = argparse.ArgumentParser(
        description="Collect FDB table from access switch(es) and store to DB."
    )
    parser.add_argument("--ip", help="Override switch IP (skip DB lookup)")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print collected entries; do not write to DB",
    )
    args = parser.parse_args()

    if args.dry_run and args.ip:
        # No DB needed: IP is explicit and we only print results
        switch_ips = [args.ip]
        db = None
    else:
        db = Database()
        await db.connect()
        await db.ensure_partitions(4)
        if args.ip:
            switch_ips = [args.ip]
        else:
            switches = await db.get_switches(is_core=False)
            if not switches:
                print("No access switches found in DB (is_core=false, enabled=true).")
                await db.close()
                return
            switch_ips = [str(sw["ip_address"]) for sw in switches]

    try:
        for ip in switch_ips:
            print(f"[{ip}] polling FDB table...")
            collector = FdbCollector(ip)
            entries = await collector.collect_async()
            print(f"[{ip}] {len(entries)} MAC entries collected")

            if args.dry_run:
                for e in entries:
                    vlans  = ",".join(str(v) for v in e.vlan_ids)
                    ifaces = ",".join(e.interfaces)
                    print(f"  {e.mac_address} | switch={e.switch_ips} | vlan={vlans} | {ifaces}")
            else:
                await db.upsert_macs(entries, switch_ip=ip)
                print(f"[{ip}] upsert_macs done")
    finally:
        if db:
            await db.close()


if __name__ == "__main__":
    asyncio.run(_main())
