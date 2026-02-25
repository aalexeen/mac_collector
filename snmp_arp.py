#!/usr/bin/env python3
"""Collect ARP table from Cisco switch via SNMP."""

import os
import subprocess
import sys
from datetime import datetime

COMMUNITY = os.environ.get("SNMP_COMMUNITY", "")

OID_ARP_MAC = ".1.3.6.1.2.1.4.22.1.2"   # ipNetToMediaPhysAddress
OID_ARP_TYPE = ".1.3.6.1.2.1.4.22.1.4"  # ipNetToMediaType
OID_IF_NAME = ".1.3.6.1.2.1.31.1.1.1.1" # ifName

TYPES = {1: "other", 2: "invalid", 3: "dynamic", 4: "static"}


def snmpwalk(ip, oid):
    result = subprocess.run(
        ["snmpwalk", "-v2c", "-c", COMMUNITY, ip, oid],
        capture_output=True, text=True
    )
    if not result.stdout.strip():
        return []
    return result.stdout.strip().split("\n")


def parse_arp_mac(lines):
    entries = {}
    for line in lines:
        try:
            oid_part, value_part = line.split(" = Hex-STRING: ")
            parts = oid_part.split(".")
            ip_addr = ".".join(parts[-4:])
            ifindex = int(parts[-5])
            mac = ":".join(value_part.strip().split())
            entries[(ifindex, ip_addr)] = mac
        except (ValueError, IndexError):
            continue
    return entries


def parse_arp_type(lines):
    entries = {}
    for line in lines:
        try:
            oid_part, value_part = line.split(" = INTEGER: ")
            parts = oid_part.split(".")
            ip_addr = ".".join(parts[-4:])
            ifindex = int(parts[-5])
            entries[(ifindex, ip_addr)] = int(value_part.strip())
        except (ValueError, IndexError):
            continue
    return entries


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
    if len(sys.argv) < 2:
        print("Usage: snmp_arp.py <switch_ip> [vlan_id]")
        sys.exit(1)

    ip = sys.argv[1]
    vlan_filter = int(sys.argv[2]) if len(sys.argv) > 2 else None
    save_to_file = vlan_filter is None

    arp_mac = parse_arp_mac(snmpwalk(ip, OID_ARP_MAC))
    arp_type = parse_arp_type(snmpwalk(ip, OID_ARP_TYPE))
    ifnames = parse_if_names(snmpwalk(ip, OID_IF_NAME))

    results = []
    for (ifindex, ip_addr), mac in arp_mac.items():
        ifname = ifnames.get(ifindex, f"ifindex-{ifindex}")
        if vlan_filter and not ifname.lower().startswith(f"vl") or \
           vlan_filter and ifname.lower() not in (f"vlan{vlan_filter}", f"vl{vlan_filter}"):
            continue
        type_int = arp_type.get((ifindex, ip_addr), 1)
        type_str = TYPES.get(type_int, "other")
        results.append(f"{mac} || {ip_addr} || {ifname} || {type_str}")

    output = "\n".join(results)

    if save_to_file:
        filename = f"{ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, "w") as f:
            f.write(output + "\n")
        print(f"{len(results)} ARP entries -> {filename}")
    else:
        print(output)


if __name__ == "__main__":
    main()
