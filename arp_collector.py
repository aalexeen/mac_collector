"""ARP table collector for core Cisco switch via SNMP.

Polls ipNetToMediaTable (OIDs .4.22.1.*) and ifName, returns a list
of ArpEntry objects ready for Database.upsert_arp().

Run standalone (reads core switch IPs from DB, writes results back):

    python arp_collector.py
    python arp_collector.py --dry-run          # print entries, no DB write
    python arp_collector.py --ip 192.168.1.1 # override IP from DB

One ArpEntry per unique MAC address.  Multiple IPs / VLANs / interfaces
are aggregated into sorted lists — this handles multi-homed hosts and
network loops without data loss.

Only dynamic (type=3) and static (type=4) ARP entries are collected;
invalid (type=2) and other (type=1) entries are skipped.
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

from db import ArpEntry


class ArpCollector:
    """Collect ARP table from a Cisco L3 core switch via SNMP.

    Usage::

        collector = ArpCollector("192.168.1.1")
        entries = collector.collect()          # synchronous
        entries = await collector.collect_async()  # async (runs in thread)
    """

    OID_ARP_MAC = ".1.3.6.1.2.1.4.22.1.2"   # ipNetToMediaPhysAddress
    OID_ARP_TYPE = ".1.3.6.1.2.1.4.22.1.4"  # ipNetToMediaType
    OID_IF_NAME = ".1.3.6.1.2.1.31.1.1.1.1" # ifName

    # ipNetToMediaType values to keep
    _KEEP_TYPES = {3, 4}  # 3=dynamic, 4=static  (skip 1=other, 2=invalid)

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

    def _snmpwalk(self, oid: str) -> list[str]:
        """Run snmpwalk and return non-empty output lines.

        Raises:
            FileNotFoundError:        snmpwalk binary not found.
            subprocess.TimeoutExpired: switch unreachable or slow.
        """
        result = subprocess.run(
            ["snmpwalk", "-v2c", "-c", self.community, self.ip, oid],
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

    def _parse_arp_mac(self, lines: list[str]) -> dict[tuple[int, str], str]:
        """Parse ipNetToMediaPhysAddress output.

        OID suffix structure: ...{ifindex}.{ip1}.{ip2}.{ip3}.{ip4}
        Value format: ``Hex-STRING: AA BB CC DD EE FF``

        Returns:
            Mapping of (ifindex, ip_addr) → mac_address (colon-separated,
            upper-case, e.g. ``"AA:BB:CC:DD:EE:FF"``).
        """
        entries: dict[tuple[int, str], str] = {}
        for line in lines:
            try:
                oid_part, value_part = line.split(" = Hex-STRING: ", 1)
                parts = oid_part.split(".")
                ip_addr = ".".join(parts[-4:])
                ifindex = int(parts[-5])
                mac = ":".join(b.upper() for b in value_part.strip().split())
                entries[(ifindex, ip_addr)] = mac
            except (ValueError, IndexError):
                continue
        return entries

    def _parse_arp_type(self, lines: list[str]) -> dict[tuple[int, str], int]:
        """Parse ipNetToMediaType output.

        Returns:
            Mapping of (ifindex, ip_addr) → type integer
            (1=other, 2=invalid, 3=dynamic, 4=static).
        """
        entries: dict[tuple[int, str], int] = {}
        for line in lines:
            try:
                oid_part, value_part = line.split(" = INTEGER: ", 1)
                parts = oid_part.split(".")
                ip_addr = ".".join(parts[-4:])
                ifindex = int(parts[-5])
                entries[(ifindex, ip_addr)] = int(value_part.strip())
            except (ValueError, IndexError):
                continue
        return entries

    def _parse_if_names(self, lines: list[str]) -> dict[int, str]:
        """Parse ifName output.

        Returns:
            Mapping of ifindex → interface name string (e.g. ``"Vlan208"``).
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

    @staticmethod
    def _vlan_from_ifname(ifname: str) -> int | None:
        """Extract VLAN number from a Cisco VLAN SVI interface name.

        Examples::

            "Vlan208"  → 208
            "Vl100"    → 100
            "Gi1/0/1"  → None
            "Loopback0" → None
        """
        lower = ifname.lower()
        for prefix in ("vlan", "vl"):
            if lower.startswith(prefix):
                try:
                    return int(lower[len(prefix):])
                except ValueError:
                    return None
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def collect(self) -> list[ArpEntry]:
        """Poll the switch ARP table and return one ArpEntry per unique MAC.

        Performs three snmpwalk calls (MAC addresses, entry types, interface
        names), filters out non-dynamic/static entries, groups by MAC address,
        and returns sorted ArpEntry objects.

        Returns:
            list[ArpEntry] — one entry per unique MAC, fields sorted.

        Raises:
            FileNotFoundError:        snmpwalk binary not found.
            subprocess.TimeoutExpired: switch unreachable or slow.
        """
        arp_mac = self._parse_arp_mac(self._snmpwalk(self.OID_ARP_MAC))
        arp_type = self._parse_arp_type(self._snmpwalk(self.OID_ARP_TYPE))
        ifnames = self._parse_if_names(self._snmpwalk(self.OID_IF_NAME))

        # Aggregate per MAC address.
        # A single MAC may appear on several VLAN interfaces (multi-homing /
        # network loop) → collect all IPs, VLANs, and interface names.
        by_mac: dict[str, dict[str, set]] = defaultdict(
            lambda: {"ip_addresses": set(), "vlan_ids": set(), "interfaces": set()}
        )

        for (ifindex, ip_addr), mac in arp_mac.items():
            type_int = arp_type.get((ifindex, ip_addr), 1)
            if type_int not in self._KEEP_TYPES:
                continue

            ifname = ifnames.get(ifindex, f"ifindex-{ifindex}")
            vlan_id = self._vlan_from_ifname(ifname)

            by_mac[mac]["ip_addresses"].add(ip_addr)
            by_mac[mac]["interfaces"].add(ifname)
            if vlan_id is not None:
                by_mac[mac]["vlan_ids"].add(vlan_id)

        return [
            ArpEntry(
                mac_address=mac,
                ip_addresses=sorted(data["ip_addresses"]),
                vlan_ids=sorted(data["vlan_ids"]),
                interfaces=sorted(data["interfaces"]),
            )
            for mac, data in by_mac.items()
        ]

    async def collect_async(self) -> list[ArpEntry]:
        """Async wrapper: runs collect() in a thread-pool executor.

        Use this from async code to avoid blocking the event loop::

            entries = await collector.collect_async()
            await db.upsert_arp(entries)
        """
        return await asyncio.to_thread(self.collect)


# ------------------------------------------------------------------
# CLI entry point
# ------------------------------------------------------------------

async def _main():
    import argparse
    from db import Database

    parser = argparse.ArgumentParser(
        description="Collect ARP table from core switch(es) and store to DB."
    )
    parser.add_argument("--ip", help="Override switch IP (skip DB lookup)")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print collected entries; do not write to DB",
    )
    args = parser.parse_args()

    db = Database()
    await db.connect()
    await db.ensure_partitions(4)

    try:
        if args.ip:
            switch_ips = [args.ip]
        else:
            switches = await db.get_switches(is_core=True)
            if not switches:
                print("No core switches found in DB (is_core=true, enabled=true).")
                return
            switch_ips = [str(sw["ip_address"]) for sw in switches]

        for ip in switch_ips:
            print(f"[{ip}] polling ARP table...")
            collector = ArpCollector(ip)
            entries = await collector.collect_async()
            print(f"[{ip}] {len(entries)} MAC entries collected")

            if args.dry_run:
                for e in entries:
                    vlans = ",".join(str(v) for v in e.vlan_ids)
                    ifaces = ",".join(e.interfaces)
                    ips = ",".join(e.ip_addresses)
                    print(f"  {e.mac_address} | {ips} | vlan={vlans} | {ifaces}")
            else:
                await db.upsert_arp(entries)
                print(f"[{ip}] upsert_arp done")
    finally:
        await db.close()


if __name__ == "__main__":
    asyncio.run(_main())
