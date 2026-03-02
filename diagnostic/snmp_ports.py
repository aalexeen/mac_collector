#!/usr/bin/env python3
"""Show switch port modes (trunk/access) via SNMP."""

import os
import subprocess
import sys

COMMUNITY = os.environ.get("SNMP_COMMUNITY", "")

OID_IF_NAME = ".1.3.6.1.2.1.31.1.1.1.1"
OID_TRUNK_STATE = ".1.3.6.1.4.1.9.9.46.1.6.1.1.13"   # vlanTrunkPortDynamicState
OID_TRUNK_STATUS = ".1.3.6.1.4.1.9.9.46.1.6.1.1.14"   # vlanTrunkPortDynamicStatus

STATES = {1: "on(trunk)", 2: "off(access)", 3: "desirable", 4: "auto", 5: "nonegotiate"}
STATUSES = {1: "trunking", 2: "notTrunking"}


def snmpwalk(ip, oid):
    result = subprocess.run(
        ["snmpwalk", "-v2c", "-c", COMMUNITY, ip, oid],
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


def parse_str_map(lines):
    m = {}
    for line in lines:
        try:
            oid_part, val = line.split(" = STRING: ")
            m[int(oid_part.split(".")[-1])] = val.strip()
        except (ValueError, IndexError):
            continue
    return m


def main():
    if len(sys.argv) < 2:
        print("Usage: snmp_ports.py <switch_ip>")
        sys.exit(1)

    ip = sys.argv[1]

    ifnames = parse_str_map(snmpwalk(ip, OID_IF_NAME))
    states = parse_int_map(snmpwalk(ip, OID_TRUNK_STATE))
    statuses = parse_int_map(snmpwalk(ip, OID_TRUNK_STATUS))

    print(f"{'Interface':<25} {'Configured':<15} {'Actual':<15} {'Mode'}")
    print("-" * 70)
    for ifidx in sorted(states.keys()):
        name = ifnames.get(ifidx, f"ifindex-{ifidx}")
        state_val = states[ifidx]
        state = STATES.get(state_val, str(state_val))
        status_val = statuses.get(ifidx, 0)
        status = STATUSES.get(status_val, "unknown")

        # Derive actual mode
        if state_val in (1, 5):       # on / nonegotiate -> always trunk
            mode = "TRUNK"
        elif state_val == 2:           # off -> always access
            mode = "ACCESS"
        elif status_val == 1:          # desirable/auto + actually trunking
            mode = "TRUNK"
        else:                          # desirable/auto + not trunking
            mode = "ACCESS"

        print(f"{name:<25} {state:<15} {status:<15} {mode}")


if __name__ == "__main__":
    main()
