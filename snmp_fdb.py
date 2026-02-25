#!/usr/bin/env python3
"""Collect FDB (MAC address table) from Cisco switch via SNMP.
Only MAC addresses on ACCESS ports are included (trunk ports filtered out)."""

import os
import subprocess
import sys
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
COMMUNITY = os.environ.get("SNMP_COMMUNITY", "")

OID_VTP_VLAN = ".1.3.6.1.4.1.9.9.46.1.3.1.1.2"       # vtpVlanState
OID_FDB_MAC = ".1.3.6.1.2.1.17.4.3.1.1"               # dot1dTpFdbAddress
OID_FDB_PORT = ".1.3.6.1.2.1.17.4.3.1.2"              # dot1dTpFdbPort
OID_BRIDGE_IF = ".1.3.6.1.2.1.17.1.4.1.2"             # dot1dBasePortIfIndex
OID_IF_NAME = ".1.3.6.1.2.1.31.1.1.1.1"               # ifName
OID_TRUNK_STATE = ".1.3.6.1.4.1.9.9.46.1.6.1.1.13"    # vlanTrunkPortDynamicState
OID_TRUNK_STATUS = ".1.3.6.1.4.1.9.9.46.1.6.1.1.14"   # vlanTrunkPortDynamicStatus


def snmpwalk(ip, oid, vlan=None):
    community = f"{COMMUNITY}@{vlan}" if vlan else COMMUNITY
    result = subprocess.run(
        ["snmpwalk", "-v2c", "-c", community, ip, oid],
        capture_output=True, text=True
    )
    if not result.stdout.strip():
        return []
    return result.stdout.strip().split("\n")


def parse_int_map(lines):
    m = {}
    for line in lines:
        try:
            oid_part, val = line.split(" = INTEGER: ")
            m[int(oid_part.split(".")[-1])] = int(val.strip())
        except (ValueError, IndexError):
            continue
    return m


def parse_ifnames(lines):
    m = {}
    for line in lines:
        try:
            oid_part, val = line.split(" = STRING: ")
            m[int(oid_part.split(".")[-1])] = val.strip().strip('"')
        except (ValueError, IndexError):
            continue
    return m


def get_vlans(ip):
    vlans = []
    for line in snmpwalk(ip, OID_VTP_VLAN):
        try:
            oid_part, val = line.split(" = INTEGER: ")
            vlan_id = int(oid_part.split(".")[-1])
            if int(val.strip()) == 1 and not (1002 <= vlan_id <= 1005):
                vlans.append(vlan_id)
        except (ValueError, IndexError):
            continue
    return vlans


def get_access_ifindexes(ip):
    """Return set of ifIndex values that are ACCESS ports."""
    states = parse_int_map(snmpwalk(ip, OID_TRUNK_STATE))
    statuses = parse_int_map(snmpwalk(ip, OID_TRUNK_STATUS))

    access = set()
    for ifidx, state_val in states.items():
        status_val = statuses.get(ifidx, 0)
        if state_val in (1, 5):        # on / nonegotiate -> trunk
            continue
        elif state_val == 2:           # off -> access
            access.add(ifidx)
        elif status_val == 1:          # desirable/auto + trunking
            continue
        else:                          # desirable/auto + not trunking
            access.add(ifidx)
    return access


def parse_macs(lines):
    macs = []
    for line in lines:
        try:
            _, val = line.split("Hex-STRING: ")
            macs.append(":".join(val.strip().split()))
        except (ValueError, IndexError):
            continue
    return macs


def parse_ports(lines):
    ports = []
    for line in lines:
        try:
            _, val = line.split(" = INTEGER: ")
            ports.append(int(val.strip()))
        except (ValueError, IndexError):
            continue
    return ports


def main():
    if len(sys.argv) < 2:
        print("Usage: snmp_fdb.py <switch_ip> [vlan_id]")
        sys.exit(1)

    ip = sys.argv[1]
    vlan_filter = int(sys.argv[2]) if len(sys.argv) > 2 else None
    save_to_file = vlan_filter is None

    ifnames = parse_ifnames(snmpwalk(ip, OID_IF_NAME))
    access_ports = get_access_ifindexes(ip)
    vlans = [vlan_filter] if vlan_filter else get_vlans(ip)

    results = []
    for vlan in vlans:
        macs = parse_macs(snmpwalk(ip, OID_FDB_MAC, vlan))
        ports = parse_ports(snmpwalk(ip, OID_FDB_PORT, vlan))
        bp_map = parse_int_map(snmpwalk(ip, OID_BRIDGE_IF, vlan))

        for mac, bp in zip(macs, ports):
            ifidx = bp_map.get(bp)
            if not ifidx or ifidx not in access_ports:
                continue
            ifname = ifnames.get(ifidx, f"ifindex-{ifidx}")
            results.append(f"{mac} || {vlan} || {ifname}")

    output = "\n".join(results)

    if save_to_file:
        filename = f"{ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, "w") as f:
            f.write(output + "\n")
        print(f"{len(results)} MAC (access only) -> {filename}")
    else:
        print(output)


if __name__ == "__main__":
    main()
