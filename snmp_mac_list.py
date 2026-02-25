#!/usr/bin/env python3
"""Collect MAC address table from Cisco L2 switch via SNMP."""

import os
import subprocess
from datetime import datetime
from pathlib import Path


def _load_env():
    env_file = Path(__file__).parent / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


_load_env()

IP = "192.168.1.1"
COMMUNITY = os.environ.get("SNMP_COMMUNITY", "")

OID_FDB = ".1.3.6.1.2.1.17.7.1.2.2.1.2"       # dot1qTpFdbPort
OID_BRIDGE_PORT = ".1.3.6.1.2.1.17.1.4.1.2"    # dot1dBasePortIfIndex
OID_IF_NAME = ".1.3.6.1.2.1.31.1.1.1.1"        # ifName


def snmpwalk(oid):
    result = subprocess.run(
        ["snmpwalk", "-v2c", "-c", COMMUNITY, IP, oid],
        capture_output=True, text=True
    )
    if not result.stdout.strip():
        return []
    return result.stdout.strip().split("\n")


def parse_fdb(lines):
    entries = []
    for line in lines:
        try:
            oid_part, value_part = line.split(" = INTEGER: ")
            parts = oid_part.split(".")
            mac_octets = parts[-6:]
            vlan = int(parts[-7])
            mac = ":".join(f"{int(x):02X}" for x in mac_octets)
            bridge_port = int(value_part.strip())
            entries.append((vlan, mac, bridge_port))
        except (ValueError, IndexError):
            continue
    return entries


def parse_bridge_ports(lines):
    mapping = {}
    for line in lines:
        try:
            oid_part, value_part = line.split(" = INTEGER: ")
            bp = int(oid_part.split(".")[-1])
            mapping[bp] = int(value_part.strip())
        except (ValueError, IndexError):
            continue
    return mapping


def parse_if_names(lines):
    mapping = {}
    for line in lines:
        try:
            oid_part, value_part = line.split(" = STRING: ")
            idx = int(oid_part.split(".")[-1])
            mapping[idx] = value_part.strip()
        except (ValueError, IndexError):
            continue
    return mapping


def main():
    fdb_entries = parse_fdb(snmpwalk(OID_FDB))
    bp_to_ifindex = parse_bridge_ports(snmpwalk(OID_BRIDGE_PORT))
    ifindex_to_name = parse_if_names(snmpwalk(OID_IF_NAME))

    filename = f"macs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w") as f:
        for vlan, mac, bridge_port in fdb_entries:
            ifindex = bp_to_ifindex.get(bridge_port)
            ifname = ifindex_to_name.get(ifindex, "CPU") if ifindex else "CPU"
            f.write(f"{mac} || {vlan} || {ifname}\n")

    print(f"{len(fdb_entries)} MAC -> {filename}")


if __name__ == "__main__":
    main()
