"""Unit tests for FdbCollector (fdb_collector.py).

No network access or snmpwalk binary required — _snmpwalk is mocked
with realistic output strings captured from a live Cisco switch.

Run:
    python -m pytest tests/test_fdb_collector.py -v
"""

import os
import sys
from unittest.mock import call, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from db import MacEntry
from fdb_collector import FdbCollector


# ------------------------------------------------------------------
# Shared test data
# Realistic snmpwalk output for a single Cisco access switch
# ------------------------------------------------------------------

# vtpVlanState: VLANs 100 and 200 active, VLAN 1002 reserved (skipped)
# (kept for _parse_vlans unit tests; not used in collect() mocks)
VTP_VLAN_LINES = [
    "CISCO-VTP-MIB::vtpVlanState.1.100 = INTEGER: 1",
    "CISCO-VTP-MIB::vtpVlanState.1.200 = INTEGER: 1",
    "CISCO-VTP-MIB::vtpVlanState.1.1002 = INTEGER: 1",  # reserved — must be skipped
    "CISCO-VTP-MIB::vtpVlanState.1.300 = INTEGER: 2",   # inactive — must be skipped
]

# ifName: two physical ports
IF_NAME_LINES = [
    "IF-MIB::ifName.1 = STRING: Gi1/0/1",
    "IF-MIB::ifName.2 = STRING: Gi1/0/2",
    "IF-MIB::ifName.10 = STRING: Gi1/0/10",
]

# Trunk state/status: port 1 = access (off), port 10 = trunk (nonegotiate)
TRUNK_STATE_LINES = [
    "CISCO-VTP-MIB::vlanTrunkPortDynamicState.1 = INTEGER: 2",    # off → access
    "CISCO-VTP-MIB::vlanTrunkPortDynamicState.2 = INTEGER: 4",    # auto
    "CISCO-VTP-MIB::vlanTrunkPortDynamicState.10 = INTEGER: 5",   # nonegotiate → trunk
]
TRUNK_STATUS_LINES = [
    "CISCO-VTP-MIB::vlanTrunkPortDynamicStatus.1 = INTEGER: 2",   # notTrunking
    "CISCO-VTP-MIB::vlanTrunkPortDynamicStatus.2 = INTEGER: 2",   # notTrunking → access
    "CISCO-VTP-MIB::vlanTrunkPortDynamicStatus.10 = INTEGER: 1",  # trunking
]

# vmVlan: ACCESS port data VLAN assignments (trunk ports absent)
VM_VLAN_LINES_100 = [
    "ENTERPRISES.68.1.2.2.1.2.1 = INTEGER: 100",   # ifIndex 1 → VLAN 100
    "ENTERPRISES.68.1.2.2.1.2.2 = INTEGER: 100",   # ifIndex 2 → VLAN 100
]
VM_VLAN_LINES_100_200 = [
    "ENTERPRISES.68.1.2.2.1.2.1 = INTEGER: 100",   # ifIndex 1 → VLAN 100
    "ENTERPRISES.68.1.2.2.1.2.2 = INTEGER: 200",   # ifIndex 2 → VLAN 200
]

# vmVoiceVlanId: voice VLAN assignments for access ports
VM_VOICE_VLAN_LINES = [
    "ENTERPRISES.68.1.5.1.1.1.1 = INTEGER: 150",   # ifIndex 1 → voice VLAN 150
    "ENTERPRISES.68.1.5.1.1.1.2 = INTEGER: 150",   # ifIndex 2 → voice VLAN 150
]

# vmVoiceVlanId sentinel values that must be filtered out
VM_VOICE_VLAN_LINES_SPECIAL = [
    "ENTERPRISES.68.1.5.1.1.1.1 = INTEGER: 4096",  # none configured — must be skipped
    "ENTERPRISES.68.1.5.1.1.1.2 = INTEGER: 4095",  # untagged special — must be skipped
    "ENTERPRISES.68.1.5.1.1.1.3 = INTEGER: 0",     # untagged 802.1p — must be skipped
]

# FDB for VLAN 100: two MACs
FDB_MAC_VLAN100 = [
    "BRIDGE-MIB::dot1dTpFdbAddress.1 = Hex-STRING: AA BB CC DD EE FF",
    "BRIDGE-MIB::dot1dTpFdbAddress.2 = Hex-STRING: 11 22 33 44 55 66",
]
FDB_PORT_VLAN100 = [
    "BRIDGE-MIB::dot1dTpFdbPort.1 = INTEGER: 5",
    "BRIDGE-MIB::dot1dTpFdbPort.2 = INTEGER: 15",
]
BRIDGE_IF_VLAN100 = [
    "BRIDGE-MIB::dot1dBasePortIfIndex.5 = INTEGER: 1",    # → Gi1/0/1 (access)
    "BRIDGE-MIB::dot1dBasePortIfIndex.15 = INTEGER: 10",  # → Gi1/0/10 (trunk → filtered)
]

# FDB for VLAN 200: same first MAC, different port
FDB_MAC_VLAN200 = [
    "BRIDGE-MIB::dot1dTpFdbAddress.1 = Hex-STRING: AA BB CC DD EE FF",
]
FDB_PORT_VLAN200 = [
    "BRIDGE-MIB::dot1dTpFdbPort.1 = INTEGER: 5",
]
BRIDGE_IF_VLAN200 = [
    "BRIDGE-MIB::dot1dBasePortIfIndex.5 = INTEGER: 1",    # → Gi1/0/1 (access)
]


def _collector(ip="192.168.1.200"):
    return FdbCollector(ip=ip, community="public")


# ------------------------------------------------------------------
# _parse_vlans
# ------------------------------------------------------------------

class TestParseVlans:
    def setup_method(self):
        self.c = _collector()

    def test_basic(self):
        lines = ["CISCO-VTP-MIB::vtpVlanState.1.100 = INTEGER: 1"]
        assert self.c._parse_vlans(lines) == [100]

    def test_inactive_skipped(self):
        lines = [
            "CISCO-VTP-MIB::vtpVlanState.1.10 = INTEGER: 1",
            "CISCO-VTP-MIB::vtpVlanState.1.20 = INTEGER: 2",  # inactive
        ]
        assert self.c._parse_vlans(lines) == [10]

    def test_reserved_vlans_skipped(self):
        lines = [
            "CISCO-VTP-MIB::vtpVlanState.1.1002 = INTEGER: 1",
            "CISCO-VTP-MIB::vtpVlanState.1.1003 = INTEGER: 1",
            "CISCO-VTP-MIB::vtpVlanState.1.1004 = INTEGER: 1",
            "CISCO-VTP-MIB::vtpVlanState.1.1005 = INTEGER: 1",
            "CISCO-VTP-MIB::vtpVlanState.1.100 = INTEGER: 1",
        ]
        assert self.c._parse_vlans(lines) == [100]

    def test_returns_sorted(self):
        lines = [
            "CISCO-VTP-MIB::vtpVlanState.1.300 = INTEGER: 1",
            "CISCO-VTP-MIB::vtpVlanState.1.100 = INTEGER: 1",
            "CISCO-VTP-MIB::vtpVlanState.1.200 = INTEGER: 1",
        ]
        assert self.c._parse_vlans(lines) == [100, 200, 300]

    def test_full_fixture(self):
        result = self.c._parse_vlans(VTP_VLAN_LINES)
        assert result == [100, 200]  # 1002 reserved, 300 inactive

    def test_malformed_line_skipped(self):
        lines = [
            "garbage",
            "CISCO-VTP-MIB::vtpVlanState.1.50 = INTEGER: 1",
        ]
        assert self.c._parse_vlans(lines) == [50]

    def test_empty_input(self):
        assert self.c._parse_vlans([]) == []


# ------------------------------------------------------------------
# _parse_vm_vlan
# ------------------------------------------------------------------

class TestParseVmVlan:
    def setup_method(self):
        self.c = _collector()

    def test_basic(self):
        lines = ["ENTERPRISES.68.1.2.2.1.2.5 = INTEGER: 100"]
        assert self.c._parse_vm_vlan(lines) == {5: 100}

    def test_multiple_ports(self):
        result = self.c._parse_vm_vlan(VM_VLAN_LINES_100)
        assert result == {1: 100, 2: 100}

    def test_different_vlans(self):
        result = self.c._parse_vm_vlan(VM_VLAN_LINES_100_200)
        assert result == {1: 100, 2: 200}

    def test_malformed_line_skipped(self):
        lines = [
            "garbage",
            "ENTERPRISES.68.1.2.2.1.2.3 = INTEGER: 50",
        ]
        assert self.c._parse_vm_vlan(lines) == {3: 50}

    def test_empty_input(self):
        assert self.c._parse_vm_vlan([]) == {}

    def test_voice_vlan_fixture(self):
        """_parse_vm_vlan handles vmVoiceVlanId output identically."""
        result = self.c._parse_vm_vlan(VM_VOICE_VLAN_LINES)
        assert result == {1: 150, 2: 150}


# ------------------------------------------------------------------
# _parse_int_map
# ------------------------------------------------------------------

class TestParseIntMap:
    def setup_method(self):
        self.c = _collector()

    def test_basic(self):
        lines = ["BRIDGE-MIB::dot1dTpFdbPort.1 = INTEGER: 5"]
        assert self.c._parse_int_map(lines) == {1: 5}

    def test_multiple_entries(self):
        result = self.c._parse_int_map(FDB_PORT_VLAN100)
        assert result == {1: 5, 2: 15}

    def test_malformed_skipped(self):
        lines = ["bad line", "BRIDGE-MIB::dot1dTpFdbPort.7 = INTEGER: 3"]
        assert self.c._parse_int_map(lines) == {7: 3}

    def test_empty_input(self):
        assert self.c._parse_int_map([]) == {}


# ------------------------------------------------------------------
# _parse_fdb_macs
# ------------------------------------------------------------------

class TestParseFdbMacs:
    def setup_method(self):
        self.c = _collector()

    def test_basic(self):
        lines = ["BRIDGE-MIB::dot1dTpFdbAddress.1 = Hex-STRING: AA BB CC DD EE FF"]
        assert self.c._parse_fdb_macs(lines) == [(1, "AA:BB:CC:DD:EE:FF")]

    def test_mac_is_uppercase(self):
        lines = ["BRIDGE-MIB::dot1dTpFdbAddress.3 = Hex-STRING: aa bb cc dd ee ff"]
        assert self.c._parse_fdb_macs(lines) == [(3, "AA:BB:CC:DD:EE:FF")]

    def test_multiple_entries(self):
        result = self.c._parse_fdb_macs(FDB_MAC_VLAN100)
        assert result == [(1, "AA:BB:CC:DD:EE:FF"), (2, "11:22:33:44:55:66")]

    def test_preserves_order(self):
        lines = [
            "BRIDGE-MIB::dot1dTpFdbAddress.5 = Hex-STRING: 55 55 55 55 55 55",
            "BRIDGE-MIB::dot1dTpFdbAddress.1 = Hex-STRING: 11 11 11 11 11 11",
        ]
        result = self.c._parse_fdb_macs(lines)
        assert result[0] == (5, "55:55:55:55:55:55")
        assert result[1] == (1, "11:11:11:11:11:11")

    def test_malformed_skipped(self):
        lines = [
            "garbage line",
            "BRIDGE-MIB::dot1dTpFdbAddress.2 = Hex-STRING: BB BB BB BB BB BB",
        ]
        assert self.c._parse_fdb_macs(lines) == [(2, "BB:BB:BB:BB:BB:BB")]

    def test_empty_input(self):
        assert self.c._parse_fdb_macs([]) == []


# ------------------------------------------------------------------
# _parse_if_names
# ------------------------------------------------------------------

class TestParseIfNames:
    def setup_method(self):
        self.c = _collector()

    def test_basic(self):
        lines = ["IF-MIB::ifName.1 = STRING: Gi1/0/1"]
        assert self.c._parse_if_names(lines) == {1: "Gi1/0/1"}

    def test_strips_quotes(self):
        lines = ['IF-MIB::ifName.2 = STRING: "GigabitEthernet1/0/2"']
        assert self.c._parse_if_names(lines) == {2: "GigabitEthernet1/0/2"}

    def test_multiple_entries(self):
        result = self.c._parse_if_names(IF_NAME_LINES)
        assert result == {1: "Gi1/0/1", 2: "Gi1/0/2", 10: "Gi1/0/10"}

    def test_malformed_skipped(self):
        lines = ["bad", "IF-MIB::ifName.5 = STRING: Gi1/0/5"]
        assert self.c._parse_if_names(lines) == {5: "Gi1/0/5"}

    def test_empty_input(self):
        assert self.c._parse_if_names([]) == {}


# ------------------------------------------------------------------
# _get_access_ifindexes
# ------------------------------------------------------------------

class TestGetAccessIfindexes:
    def setup_method(self):
        self.c = _collector()

    def _mock_trunk(self, state_lines, status_lines):
        return [state_lines, status_lines]

    def test_off_is_always_access(self):
        """state=2 (off) → access regardless of status."""
        with patch.object(self.c, "_snmpwalk", side_effect=self._mock_trunk(
            ["MIB::vlanTrunkPortDynamicState.3 = INTEGER: 2"],
            [],
        )):
            assert 3 in self.c._get_access_ifindexes()

    def test_on_is_always_trunk(self):
        """state=1 (on) → trunk."""
        with patch.object(self.c, "_snmpwalk", side_effect=self._mock_trunk(
            ["MIB::vlanTrunkPortDynamicState.3 = INTEGER: 1"],
            ["MIB::vlanTrunkPortDynamicStatus.3 = INTEGER: 2"],
        )):
            assert 3 not in self.c._get_access_ifindexes()

    def test_nonegotiate_is_always_trunk(self):
        """state=5 (nonegotiate) → trunk."""
        with patch.object(self.c, "_snmpwalk", side_effect=self._mock_trunk(
            ["MIB::vlanTrunkPortDynamicState.4 = INTEGER: 5"],
            ["MIB::vlanTrunkPortDynamicStatus.4 = INTEGER: 1"],
        )):
            assert 4 not in self.c._get_access_ifindexes()

    def test_auto_trunking_is_trunk(self):
        """state=4 (auto) + status=1 (trunking) → trunk."""
        with patch.object(self.c, "_snmpwalk", side_effect=self._mock_trunk(
            ["MIB::vlanTrunkPortDynamicState.5 = INTEGER: 4"],
            ["MIB::vlanTrunkPortDynamicStatus.5 = INTEGER: 1"],
        )):
            assert 5 not in self.c._get_access_ifindexes()

    def test_auto_not_trunking_is_access(self):
        """state=4 (auto) + status=2 (notTrunking) → access."""
        with patch.object(self.c, "_snmpwalk", side_effect=self._mock_trunk(
            ["MIB::vlanTrunkPortDynamicState.6 = INTEGER: 4"],
            ["MIB::vlanTrunkPortDynamicStatus.6 = INTEGER: 2"],
        )):
            assert 6 in self.c._get_access_ifindexes()

    def test_desirable_trunking_is_trunk(self):
        """state=3 (desirable) + status=1 (trunking) → trunk."""
        with patch.object(self.c, "_snmpwalk", side_effect=self._mock_trunk(
            ["MIB::vlanTrunkPortDynamicState.7 = INTEGER: 3"],
            ["MIB::vlanTrunkPortDynamicStatus.7 = INTEGER: 1"],
        )):
            assert 7 not in self.c._get_access_ifindexes()

    def test_full_fixture(self):
        """From shared fixture: ports 1 and 2 are access, port 10 is trunk."""
        with patch.object(self.c, "_snmpwalk", side_effect=self._mock_trunk(
            TRUNK_STATE_LINES, TRUNK_STATUS_LINES,
        )):
            access = self.c._get_access_ifindexes()
        assert 1 in access    # off → access
        assert 2 in access    # auto + notTrunking → access
        assert 10 not in access  # nonegotiate → trunk

    def test_empty_responses(self):
        with patch.object(self.c, "_snmpwalk", side_effect=[[], []]):
            assert self.c._get_access_ifindexes() == set()


# ------------------------------------------------------------------
# collect()
#
# _snmpwalk call order inside collect():
#   1. OID_IF_NAME        (no vlan)
#   2. OID_TRUNK_STATE    (no vlan)  ─┐ from _get_access_ifindexes
#   3. OID_TRUNK_STATUS   (no vlan)  ─┘
#   4. OID_VM_VLAN        (no vlan)
#   5. OID_VM_VOICE_VLAN  (no vlan)
#   then for each VLAN:
#     N+0. OID_FDB_MAC   (vlan)
#     N+1. OID_FDB_PORT  (vlan)
#     N+2. OID_BRIDGE_IF (vlan)
# ------------------------------------------------------------------

class TestCollect:
    def setup_method(self):
        self.c = _collector()

    def _side_effect_one_vlan(self, ifname, state, status, vm_vlan,
                               fdb_mac, fdb_port, bridge_if):
        """Build side_effect list for a single-VLAN scenario (no voice VLANs)."""
        return [ifname, state, status, vm_vlan, [], fdb_mac, fdb_port, bridge_if]

    def test_single_mac_on_access_port(self):
        with patch.object(self.c, "_snmpwalk", side_effect=self._side_effect_one_vlan(
            IF_NAME_LINES,
            TRUNK_STATE_LINES,
            TRUNK_STATUS_LINES,
            ["ENTERPRISES.68.1.2.2.1.2.1 = INTEGER: 100"],  # ifIndex 1 → VLAN 100
            ["BRIDGE-MIB::dot1dTpFdbAddress.1 = Hex-STRING: AA BB CC DD EE FF"],
            ["BRIDGE-MIB::dot1dTpFdbPort.1 = INTEGER: 5"],
            ["BRIDGE-MIB::dot1dBasePortIfIndex.5 = INTEGER: 1"],  # → Gi1/0/1 (access)
        )):
            entries = self.c.collect()

        assert len(entries) == 1
        e = entries[0]
        assert e.mac_address == "AA:BB:CC:DD:EE:FF"
        assert e.switch_ips == ["192.168.1.200"]
        assert e.vlan_ids == [100]
        assert e.interfaces == ["Gi1/0/1"]

    def test_trunk_mac_filtered_out(self):
        """MAC on trunk port (ifidx=10) must not appear in result.

        vmVlan only contains ACCESS ports, so the MAC resolves to ifidx=10 via
        bridge-port mapping, which is not in port_set for the VLAN → filtered.
        """
        with patch.object(self.c, "_snmpwalk", side_effect=self._side_effect_one_vlan(
            IF_NAME_LINES,
            TRUNK_STATE_LINES,
            TRUNK_STATUS_LINES,
            ["ENTERPRISES.68.1.2.2.1.2.1 = INTEGER: 100"],  # only ifidx 1 in port_set
            ["BRIDGE-MIB::dot1dTpFdbAddress.1 = Hex-STRING: AA BB CC DD EE FF"],
            ["BRIDGE-MIB::dot1dTpFdbPort.1 = INTEGER: 15"],
            ["BRIDGE-MIB::dot1dBasePortIfIndex.15 = INTEGER: 10"],  # trunk → not in port_set
        )):
            entries = self.c.collect()

        assert entries == []

    def test_two_vlans_same_mac_aggregated(self):
        """Same MAC seen on VLAN 100 and 200 → one MacEntry with both VLANs."""
        with patch.object(self.c, "_snmpwalk", side_effect=[
            IF_NAME_LINES,          # ifnames
            TRUNK_STATE_LINES,      # trunk state
            TRUNK_STATUS_LINES,     # trunk status
            VM_VLAN_LINES_100_200,  # ifidx 1→VLAN100, ifidx 2→VLAN200
            [],                     # no voice VLANs
            # VLAN 100 (port_set={1})
            FDB_MAC_VLAN100[:1],    # only first MAC: AA:BB:CC:DD:EE:FF
            FDB_PORT_VLAN100[:1],
            BRIDGE_IF_VLAN100[:1],
            # VLAN 200 (port_set={2})
            FDB_MAC_VLAN200,
            FDB_PORT_VLAN200,
            BRIDGE_IF_VLAN200,
        ]):
            entries = self.c.collect()

        assert len(entries) == 1
        e = entries[0]
        assert e.mac_address == "AA:BB:CC:DD:EE:FF"
        assert e.vlan_ids == [100, 200]
        assert e.interfaces == ["Gi1/0/1"]  # same port in both VLANs

    def test_two_distinct_macs_same_vlan(self):
        """Two different MACs on VLAN 100 → two MacEntry objects."""
        with patch.object(self.c, "_snmpwalk", side_effect=self._side_effect_one_vlan(
            IF_NAME_LINES,
            TRUNK_STATE_LINES,
            TRUNK_STATUS_LINES,
            [
                "ENTERPRISES.68.1.2.2.1.2.1 = INTEGER: 100",  # ifidx 1 → VLAN 100
                "ENTERPRISES.68.1.2.2.1.2.2 = INTEGER: 100",  # ifidx 2 → VLAN 100
            ],
            FDB_MAC_VLAN100,    # AA:BB:... and 11:22:...
            FDB_PORT_VLAN100,
            [
                "BRIDGE-MIB::dot1dBasePortIfIndex.5 = INTEGER: 1",   # → Gi1/0/1 (access)
                "BRIDGE-MIB::dot1dBasePortIfIndex.15 = INTEGER: 2",  # → Gi1/0/2 (access)
            ],
        )):
            entries = self.c.collect()

        macs = {e.mac_address for e in entries}
        assert len(entries) == 2
        assert "AA:BB:CC:DD:EE:FF" in macs
        assert "11:22:33:44:55:66" in macs

    def test_mixed_access_and_trunk_macs(self):
        """One MAC on access, one resolves to trunk ifidx — only access MAC returned."""
        with patch.object(self.c, "_snmpwalk", side_effect=self._side_effect_one_vlan(
            IF_NAME_LINES,
            TRUNK_STATE_LINES,
            TRUNK_STATUS_LINES,
            ["ENTERPRISES.68.1.2.2.1.2.1 = INTEGER: 100"],  # port_set={1} for VLAN 100
            FDB_MAC_VLAN100,    # AA:BB → bridge port 5→ifidx 1 (in port_set)
                                # 11:22 → bridge port 15→ifidx 10 (not in port_set)
            FDB_PORT_VLAN100,
            BRIDGE_IF_VLAN100,
        )):
            entries = self.c.collect()

        assert len(entries) == 1
        assert entries[0].mac_address == "AA:BB:CC:DD:EE:FF"

    def test_no_vm_vlan_data(self):
        """Empty vmVlan and vmVoiceVlan → no VLANs → empty result."""
        with patch.object(self.c, "_snmpwalk", side_effect=[
            IF_NAME_LINES,
            TRUNK_STATE_LINES,
            TRUNK_STATUS_LINES,
            [],  # no vmVlan data
            [],  # no vmVoiceVlan data
        ]):
            assert self.c.collect() == []

    def test_reserved_vlan_skipped(self):
        """vmVlan entries for reserved VLANs (1002–1005) are excluded."""
        with patch.object(self.c, "_snmpwalk", side_effect=[
            IF_NAME_LINES,
            TRUNK_STATE_LINES,
            TRUNK_STATUS_LINES,
            [
                "ENTERPRISES.68.1.2.2.1.2.1 = INTEGER: 1002",  # reserved → skip
                "ENTERPRISES.68.1.2.2.1.2.2 = INTEGER: 1003",  # reserved → skip
            ],
            [],  # no voice VLAN
        ]):
            assert self.c.collect() == []

    def test_vm_vlan_trunk_port_filtered(self):
        """vmVlan entry for a trunk ifidx is ignored (not in access_ports)."""
        with patch.object(self.c, "_snmpwalk", side_effect=[
            IF_NAME_LINES,
            TRUNK_STATE_LINES,      # ifidx 10 is trunk
            TRUNK_STATUS_LINES,
            [
                "ENTERPRISES.68.1.2.2.1.2.10 = INTEGER: 100",  # trunk port → filtered
            ],
            [],  # no voice VLAN
        ]):
            assert self.c.collect() == []

    def test_switch_ip_stored_in_entry(self):
        """switch_ips must contain the collector's own IP."""
        c = FdbCollector(ip="10.0.0.1", community="public")
        with patch.object(c, "_snmpwalk", side_effect=self._side_effect_one_vlan(
            ["IF-MIB::ifName.1 = STRING: Gi1/0/1"],
            ["MIB::vlanTrunkPortDynamicState.1 = INTEGER: 2"],   # access
            [],
            ["ENTERPRISES.68.1.2.2.1.2.1 = INTEGER: 10"],        # ifidx 1 → VLAN 10
            ["BRIDGE-MIB::dot1dTpFdbAddress.1 = Hex-STRING: AA BB CC DD EE FF"],
            ["BRIDGE-MIB::dot1dTpFdbPort.1 = INTEGER: 5"],
            ["BRIDGE-MIB::dot1dBasePortIfIndex.5 = INTEGER: 1"],
        )):
            entries = c.collect()

        assert entries[0].switch_ips == ["10.0.0.1"]

    def test_missing_bridge_port_skipped(self):
        """MAC whose bridge port has no ifIndex mapping is silently skipped."""
        with patch.object(self.c, "_snmpwalk", side_effect=self._side_effect_one_vlan(
            IF_NAME_LINES,
            TRUNK_STATE_LINES,
            TRUNK_STATUS_LINES,
            ["ENTERPRISES.68.1.2.2.1.2.1 = INTEGER: 100"],
            ["BRIDGE-MIB::dot1dTpFdbAddress.1 = Hex-STRING: AA BB CC DD EE FF"],
            ["BRIDGE-MIB::dot1dTpFdbPort.1 = INTEGER: 99"],
            [],  # no bridge-port-to-ifindex mapping
        )):
            assert self.c.collect() == []

    def test_missing_ifname_uses_fallback(self):
        """ifindex not in ifName walk → interface named 'ifindex-N'."""
        with patch.object(self.c, "_snmpwalk", side_effect=self._side_effect_one_vlan(
            [],  # empty ifName
            ["MIB::vlanTrunkPortDynamicState.1 = INTEGER: 2"],   # access
            [],
            ["ENTERPRISES.68.1.2.2.1.2.1 = INTEGER: 10"],
            ["BRIDGE-MIB::dot1dTpFdbAddress.1 = Hex-STRING: AA BB CC DD EE FF"],
            ["BRIDGE-MIB::dot1dTpFdbPort.1 = INTEGER: 5"],
            ["BRIDGE-MIB::dot1dBasePortIfIndex.5 = INTEGER: 1"],
        )):
            entries = self.c.collect()

        assert entries[0].interfaces == ["ifindex-1"]

    def test_returns_list_of_mac_entry(self):
        with patch.object(self.c, "_snmpwalk", side_effect=self._side_effect_one_vlan(
            IF_NAME_LINES,
            TRUNK_STATE_LINES,
            TRUNK_STATUS_LINES,
            ["ENTERPRISES.68.1.2.2.1.2.1 = INTEGER: 100"],
            FDB_MAC_VLAN100[:1],
            FDB_PORT_VLAN100[:1],
            BRIDGE_IF_VLAN100[:1],
        )):
            entries = self.c.collect()

        assert isinstance(entries, list)
        assert all(isinstance(e, MacEntry) for e in entries)

    def test_returns_sorted_lists(self):
        """switch_ips, vlan_ids, interfaces are sorted."""
        with patch.object(self.c, "_snmpwalk", side_effect=[
            IF_NAME_LINES,
            TRUNK_STATE_LINES,
            TRUNK_STATUS_LINES,
            VM_VLAN_LINES_100_200,   # ifidx 1→VLAN100, ifidx 2→VLAN200
            [],                      # no voice VLANs
            # VLAN 100 — same MAC, access port Gi1/0/1 (ifidx 1)
            FDB_MAC_VLAN100[:1],
            FDB_PORT_VLAN100[:1],
            BRIDGE_IF_VLAN100[:1],
            # VLAN 200 — same MAC, access port Gi1/0/2 (ifidx 2)
            FDB_MAC_VLAN200,
            FDB_PORT_VLAN200,
            [
                "BRIDGE-MIB::dot1dBasePortIfIndex.5 = INTEGER: 2",  # → Gi1/0/2 (access)
            ],
        ]):
            entries = self.c.collect()

        e = entries[0]
        assert e.vlan_ids == sorted(e.vlan_ids)
        assert e.interfaces == sorted(e.interfaces)
        assert e.switch_ips == sorted(e.switch_ips)

    def test_all_empty_snmp_responses(self):
        with patch.object(self.c, "_snmpwalk", side_effect=[[], [], [], [], []]):
            assert self.c.collect() == []

    def test_only_access_vlan_ports_queried(self):
        """When vlan_to_ports is empty, no FDB walks occur — verify call count."""
        mock = patch.object(self.c, "_snmpwalk", side_effect=[
            [],    # ifnames
            [],    # trunk state
            [],    # trunk status
            [],    # vmVlan → empty
            [],    # vmVoiceVlan → empty → vlan_to_ports empty → early return
        ])
        with mock as m:
            result = self.c.collect()

        assert result == []
        assert m.call_count == 5  # 5 setup calls, no per-VLAN calls

    def test_per_vlan_call_count(self):
        """With one ACCESS VLAN, exactly 3 additional FDB walks are made."""
        mock = patch.object(self.c, "_snmpwalk", side_effect=[
            [],    # ifnames
            ["MIB::vlanTrunkPortDynamicState.1 = INTEGER: 2"],  # port 1 = access
            [],    # trunk status
            ["ENTERPRISES.68.1.2.2.1.2.1 = INTEGER: 100"],       # port 1 → VLAN 100
            [],    # vmVoiceVlan: none
            [], [], [],  # FDB MAC, PORT, BRIDGE_IF for VLAN 100
        ])
        with mock as m:
            self.c.collect()

        assert m.call_count == 8  # 5 setup + 3 per-VLAN

    # ------------------------------------------------------------------
    # Voice VLAN tests
    # ------------------------------------------------------------------

    def test_voice_vlan_mac_collected(self):
        """MAC on a voice VLAN port is included in results."""
        with patch.object(self.c, "_snmpwalk", side_effect=[
            IF_NAME_LINES,
            TRUNK_STATE_LINES,
            TRUNK_STATUS_LINES,
            [],                  # no data VLANs
            VM_VOICE_VLAN_LINES, # ifidx 1 and 2 → voice VLAN 150
            # VLAN 150 FDB (port_set={1, 2})
            ["BRIDGE-MIB::dot1dTpFdbAddress.1 = Hex-STRING: AA BB CC DD EE FF"],
            ["BRIDGE-MIB::dot1dTpFdbPort.1 = INTEGER: 5"],
            ["BRIDGE-MIB::dot1dBasePortIfIndex.5 = INTEGER: 1"],  # → Gi1/0/1 (access)
        ]):
            entries = self.c.collect()

        assert len(entries) == 1
        e = entries[0]
        assert e.mac_address == "AA:BB:CC:DD:EE:FF"
        assert e.vlan_ids == [150]
        assert e.interfaces == ["Gi1/0/1"]

    def test_voice_vlan_merged_with_data_vlan(self):
        """Same ifIndex in vmVlan (data) and vmVoiceVlanId — both VLANs collected."""
        with patch.object(self.c, "_snmpwalk", side_effect=[
            IF_NAME_LINES,
            TRUNK_STATE_LINES,
            TRUNK_STATUS_LINES,
            ["ENTERPRISES.68.1.2.2.1.2.1 = INTEGER: 100"],  # data VLAN 100 on ifidx 1
            ["ENTERPRISES.68.1.5.1.1.1.1 = INTEGER: 150"],  # voice VLAN 150 on ifidx 1
            # VLAN 100 FDB (port_set={1})
            ["BRIDGE-MIB::dot1dTpFdbAddress.1 = Hex-STRING: AA BB CC DD EE FF"],
            ["BRIDGE-MIB::dot1dTpFdbPort.1 = INTEGER: 5"],
            ["BRIDGE-MIB::dot1dBasePortIfIndex.5 = INTEGER: 1"],
            # VLAN 150 FDB (port_set={1})
            ["BRIDGE-MIB::dot1dTpFdbAddress.1 = Hex-STRING: AA BB CC DD EE FF"],
            ["BRIDGE-MIB::dot1dTpFdbPort.1 = INTEGER: 5"],
            ["BRIDGE-MIB::dot1dBasePortIfIndex.5 = INTEGER: 1"],
        ]):
            entries = self.c.collect()

        assert len(entries) == 1
        e = entries[0]
        assert e.mac_address == "AA:BB:CC:DD:EE:FF"
        assert 100 in e.vlan_ids
        assert 150 in e.vlan_ids

    def test_voice_vlan_4096_filtered(self):
        """vmVoiceVlanId value 4096 (no voice VLAN configured) must be skipped."""
        with patch.object(self.c, "_snmpwalk", side_effect=[
            IF_NAME_LINES,
            TRUNK_STATE_LINES,
            TRUNK_STATUS_LINES,
            [],
            ["ENTERPRISES.68.1.5.1.1.1.1 = INTEGER: 4096"],  # sentinel → skip
        ]):
            assert self.c.collect() == []

    def test_voice_vlan_4095_filtered(self):
        """vmVoiceVlanId value 4095 (untagged special mode) must be skipped."""
        with patch.object(self.c, "_snmpwalk", side_effect=[
            IF_NAME_LINES,
            TRUNK_STATE_LINES,
            TRUNK_STATUS_LINES,
            [],
            ["ENTERPRISES.68.1.5.1.1.1.1 = INTEGER: 4095"],  # untagged → skip
        ]):
            assert self.c.collect() == []

    def test_voice_vlan_0_filtered(self):
        """vmVoiceVlanId value 0 (untagged 802.1p mode) must be skipped."""
        with patch.object(self.c, "_snmpwalk", side_effect=[
            IF_NAME_LINES,
            TRUNK_STATE_LINES,
            TRUNK_STATUS_LINES,
            [],
            ["ENTERPRISES.68.1.5.1.1.1.1 = INTEGER: 0"],  # untagged → skip
        ]):
            assert self.c.collect() == []

    def test_voice_vlan_trunk_port_filtered(self):
        """Voice VLAN entry for a trunk ifidx is ignored (not in access_ports)."""
        with patch.object(self.c, "_snmpwalk", side_effect=[
            IF_NAME_LINES,
            TRUNK_STATE_LINES,      # ifidx 10 is trunk
            TRUNK_STATUS_LINES,
            [],
            ["ENTERPRISES.68.1.5.1.1.1.10 = INTEGER: 150"],  # trunk port → filtered
        ]):
            assert self.c.collect() == []

    def test_voice_vlan_mixed_sentinels_and_valid(self):
        """Sentinel values filtered while valid voice VLAN passes through."""
        with patch.object(self.c, "_snmpwalk", side_effect=[
            IF_NAME_LINES,
            TRUNK_STATE_LINES,
            TRUNK_STATUS_LINES,
            [],
            VM_VOICE_VLAN_LINES_SPECIAL + [
                "ENTERPRISES.68.1.5.1.1.1.1 = INTEGER: 150",  # valid → included
            ],
            # VLAN 150 FDB: one MAC on ifidx 1 (access)
            ["BRIDGE-MIB::dot1dTpFdbAddress.1 = Hex-STRING: AA BB CC DD EE FF"],
            ["BRIDGE-MIB::dot1dTpFdbPort.1 = INTEGER: 5"],
            ["BRIDGE-MIB::dot1dBasePortIfIndex.5 = INTEGER: 1"],
        ]):
            entries = self.c.collect()

        assert len(entries) == 1
        assert entries[0].vlan_ids == [150]

    def test_voice_vlan_reserved_skipped(self):
        """vmVoiceVlanId in reserved range (1002–1005) is excluded."""
        with patch.object(self.c, "_snmpwalk", side_effect=[
            IF_NAME_LINES,
            TRUNK_STATE_LINES,
            TRUNK_STATUS_LINES,
            [],
            ["ENTERPRISES.68.1.5.1.1.1.1 = INTEGER: 1002"],  # reserved → skip
        ]):
            assert self.c.collect() == []


# ------------------------------------------------------------------
# collect_async()
# ------------------------------------------------------------------

class TestCollectAsync:
    @pytest.mark.asyncio
    async def test_async_returns_same_entries_as_sync(self):
        c = _collector()
        with patch.object(c, "_snmpwalk", side_effect=[
            IF_NAME_LINES,
            TRUNK_STATE_LINES,
            TRUNK_STATUS_LINES,
            ["ENTERPRISES.68.1.2.2.1.2.1 = INTEGER: 100"],
            [],                    # no voice VLANs
            FDB_MAC_VLAN100[:1],
            FDB_PORT_VLAN100[:1],
            BRIDGE_IF_VLAN100[:1],
        ]):
            entries = await c.collect_async()

        assert len(entries) == 1
        assert entries[0].mac_address == "AA:BB:CC:DD:EE:FF"
        assert entries[0].vlan_ids == [100]

    @pytest.mark.asyncio
    async def test_async_empty(self):
        c = _collector()
        with patch.object(c, "_snmpwalk", side_effect=[[], [], [], [], []]):
            assert await c.collect_async() == []


# ------------------------------------------------------------------
# Constructor
# ------------------------------------------------------------------

class TestFdbCollectorInit:
    def test_community_from_arg(self):
        c = FdbCollector("1.2.3.4", community="mysecret")
        assert c.community == "mysecret"

    def test_community_from_env(self, monkeypatch):
        monkeypatch.setenv("SNMP_COMMUNITY", "envcomm")
        c = FdbCollector("1.2.3.4")
        assert c.community == "envcomm"

    def test_arg_takes_precedence_over_env(self, monkeypatch):
        monkeypatch.setenv("SNMP_COMMUNITY", "envcomm")
        c = FdbCollector("1.2.3.4", community="argcomm")
        assert c.community == "argcomm"

    def test_default_timeout(self):
        assert FdbCollector("1.2.3.4", community="x").timeout == 30

    def test_custom_timeout(self):
        assert FdbCollector("1.2.3.4", community="x", timeout=60).timeout == 60

    def test_ip_stored(self):
        c = FdbCollector("192.168.1.200", community="pub")
        assert c.ip == "192.168.1.200"
