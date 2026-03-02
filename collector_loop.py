"""Background collector loop for Docker demo.

Runs FDB + ARP collection on all enabled switches every COLLECT_INTERVAL seconds.
Errors are logged but do not stop the loop.
"""

import asyncio
import os
import sys

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

COLLECT_INTERVAL = int(os.environ.get("COLLECT_INTERVAL", "300"))  # seconds


async def run_once():
    from db import Database
    from fdb_collector import FdbCollector
    from arp_collector import ArpCollector

    db = Database()
    await db.connect()
    try:
        await db.ensure_partitions(4)
        switches = await db.get_switches()

        access_switches = [sw for sw in switches if not sw["is_core"] and sw["enabled"]]
        core_switches   = [sw for sw in switches if sw["is_core"]     and sw["enabled"]]

        community = os.environ.get("SNMP_COMMUNITY", "")

        # FDB — access switches
        for sw in access_switches:
            ip = str(sw["ip_address"])
            print(f"[collector] FDB polling {ip}...", flush=True)
            try:
                collector = FdbCollector(ip=ip, community=community)
                entries = await collector.collect_async()
                changed, gone = await db.upsert_macs(entries, switch_ip=ip)
                print(f"[collector] FDB {ip}: {len(entries)} MACs, {changed} changed, {gone} gone", flush=True)
            except Exception as exc:
                print(f"[collector] FDB {ip} error: {exc}", file=sys.stderr, flush=True)

        # ARP — core switches
        for sw in core_switches:
            ip = str(sw["ip_address"])
            print(f"[collector] ARP polling {ip}...", flush=True)
            try:
                collector = ArpCollector(ip=ip, community=community)
                entries = await collector.collect_async()
                changed, _ = await db.upsert_arp(entries)
                print(f"[collector] ARP {ip}: {len(entries)} entries, {changed} changed", flush=True)
            except Exception as exc:
                print(f"[collector] ARP {ip} error: {exc}", file=sys.stderr, flush=True)

    finally:
        await db.close()


async def main():
    print(f"[collector] Starting loop, interval={COLLECT_INTERVAL}s", flush=True)
    while True:
        try:
            await run_once()
        except Exception as exc:
            print(f"[collector] Unexpected error: {exc}", file=sys.stderr, flush=True)
        await asyncio.sleep(COLLECT_INTERVAL)


if __name__ == "__main__":
    asyncio.run(main())
