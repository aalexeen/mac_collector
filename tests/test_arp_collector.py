"""Unit tests for ArpCollector (arp_collector.py).

No network access or snmpwalk binary required — _snmpwalk is mocked
with realistic output strings captured from a live Cisco switch.

Run:
    python -m pytest tests/test_arp_collector.py -v
"""

import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from arp_collector import ArpCollector
from db import ArpEntry


# ------------------------------------------------------------------
# Shared test data
# Realistic snmpwalk output for three MACs across two VLAN interfaces
# ------------------------------------------------------------------

ARP_MAC_LINES = [
    "IP-MIB::ipNetToMediaPhysAddress.208.10.0.208.10 = Hex-STRING: C0 EE 40 14 11 83",
    "IP-MIB::ipNetToMediaPhysAddress.209.10.0.209.20 = Hex-STRING: AA BB CC DD EE FF",
    "IP-MIB::ipNetToMediaPhysAddress.208.10.0.208.30 = Hex-STRING: 11 22 33 44 55 66",
]

ARP_TYPE_LINES = [
    "IP-MIB::ipNetToMediaType.208.10.0.208.10 = INTEGER: 3",   # dynamic
    "IP-MIB::ipNetToMediaType.209.10.0.209.20 = INTEGER: 4",   # static
    "IP-MIB::ipNetToMediaType.208.10.0.208.30 = INTEGER: 3",   # dynamic
]

IF_NAME_LINES = [
    "IF-MIB::ifName.208 = STRING: Vlan208",
    "IF-MIB::ifName.209 = STRING: Vlan209",
]


def _collector():
    return ArpCollector(ip="192.168.1.1", community="public")


def _mock(mac_lines, type_lines, ifname_lines):
    """Shorthand: three sequential _snmpwalk return values."""
    return [mac_lines, type_lines, ifname_lines]


# ------------------------------------------------------------------
# _parse_arp_mac
# ------------------------------------------------------------------

class TestParseArpMac:
    def setup_method(self):
        self.c = _collector()

    def test_basic(self):
        lines = ["IP-MIB::ipNetToMediaPhysAddress.208.10.0.208.10 = Hex-STRING: C0 EE 40 14 11 83"]
        assert self.c._parse_arp_mac(lines) == {(208, "10.0.208.10"): "C0:EE:40:14:11:83"}

    def test_mac_is_uppercase(self):
        lines = ["IP-MIB::ipNetToMediaPhysAddress.1.1.2.3.4 = Hex-STRING: aa bb cc dd ee ff"]
        result = self.c._parse_arp_mac(lines)
        assert result[(1, "1.2.3.4")] == "AA:BB:CC:DD:EE:FF"

    def test_multiple_entries(self):
        result = self.c._parse_arp_mac(ARP_MAC_LINES)
        assert len(result) == 3
        assert (208, "10.0.208.10") in result
        assert (209, "10.0.209.20") in result
        assert (208, "10.0.208.30") in result

    def test_malformed_line_skipped(self):
        lines = [
            "garbage line without the delimiter",
            "IP-MIB::ipNetToMediaPhysAddress.208.10.0.208.10 = Hex-STRING: C0 EE 40 14 11 83",
        ]
        assert len(self.c._parse_arp_mac(lines)) == 1

    def test_empty_input(self):
        assert self.c._parse_arp_mac([]) == {}


# ------------------------------------------------------------------
# _parse_arp_type
# ------------------------------------------------------------------

class TestParseArpType:
    def setup_method(self):
        self.c = _collector()

    def test_dynamic(self):
        lines = ["IP-MIB::ipNetToMediaType.208.10.0.208.10 = INTEGER: 3"]
        assert self.c._parse_arp_type(lines) == {(208, "10.0.208.10"): 3}

    def test_static(self):
        lines = ["IP-MIB::ipNetToMediaType.5.192.168.1.1 = INTEGER: 4"]
        assert self.c._parse_arp_type(lines) == {(5, "192.168.1.1"): 4}

    def test_all_types(self):
        result = self.c._parse_arp_type(ARP_TYPE_LINES)
        assert len(result) == 3
        assert result[(208, "10.0.208.10")] == 3
        assert result[(209, "10.0.209.20")] == 4
        assert result[(208, "10.0.208.30")] == 3

    def test_malformed_line_skipped(self):
        lines = ["bad line", "IP-MIB::ipNetToMediaType.1.1.2.3.4 = INTEGER: 3"]
        assert len(self.c._parse_arp_type(lines)) == 1

    def test_empty_input(self):
        assert self.c._parse_arp_type([]) == {}


# ------------------------------------------------------------------
# _parse_if_names
# ------------------------------------------------------------------

class TestParseIfNames:
    def setup_method(self):
        self.c = _collector()

    def test_basic(self):
        lines = ["IF-MIB::ifName.208 = STRING: Vlan208"]
        assert self.c._parse_if_names(lines) == {208: "Vlan208"}

    def test_strips_quotes(self):
        """Some snmpwalk versions wrap string values in double quotes."""
        lines = ['IF-MIB::ifName.1 = STRING: "GigabitEthernet1/0/1"']
        assert self.c._parse_if_names(lines) == {1: "GigabitEthernet1/0/1"}

    def test_multiple_entries(self):
        assert self.c._parse_if_names(IF_NAME_LINES) == {208: "Vlan208", 209: "Vlan209"}

    def test_malformed_line_skipped(self):
        lines = ["garbage", "IF-MIB::ifName.208 = STRING: Vlan208"]
        assert len(self.c._parse_if_names(lines)) == 1

    def test_empty_input(self):
        assert self.c._parse_if_names([]) == {}


# ------------------------------------------------------------------
# _vlan_from_ifname
# ------------------------------------------------------------------

class TestVlanFromIfname:
    def test_vlan_prefix(self):
        assert ArpCollector._vlan_from_ifname("Vlan208") == 208

    def test_vl_prefix(self):
        assert ArpCollector._vlan_from_ifname("Vl100") == 100

    def test_case_insensitive(self):
        assert ArpCollector._vlan_from_ifname("VLAN300") == 300
        assert ArpCollector._vlan_from_ifname("vlan1") == 1

    def test_vlan_1(self):
        assert ArpCollector._vlan_from_ifname("Vlan1") == 1

    def test_vlan_4094(self):
        assert ArpCollector._vlan_from_ifname("Vlan4094") == 4094

    def test_physical_gigabit(self):
        assert ArpCollector._vlan_from_ifname("GigabitEthernet1/0/1") is None

    def test_physical_short(self):
        assert ArpCollector._vlan_from_ifname("Gi1/0/1") is None

    def test_loopback(self):
        assert ArpCollector._vlan_from_ifname("Loopback0") is None

    def test_vlan_empty_suffix(self):
        assert ArpCollector._vlan_from_ifname("Vlan") is None

    def test_vlan_non_numeric_suffix(self):
        assert ArpCollector._vlan_from_ifname("Vlanfoo") is None


# ------------------------------------------------------------------
# collect()
# ------------------------------------------------------------------

class TestCollect:
    def setup_method(self):
        self.c = _collector()

    def test_basic_single_entry(self):
        with patch.object(self.c, "_snmpwalk", side_effect=_mock(
            ["IP-MIB::ipNetToMediaPhysAddress.208.10.0.208.10 = Hex-STRING: C0 EE 40 14 11 83"],
            ["IP-MIB::ipNetToMediaType.208.10.0.208.10 = INTEGER: 3"],
            ["IF-MIB::ifName.208 = STRING: Vlan208"],
        )):
            entries = self.c.collect()

        assert len(entries) == 1
        e = entries[0]
        assert e.mac_address == "C0:EE:40:14:11:83"
        assert e.ip_addresses == ["10.0.208.10"]
        assert e.vlan_ids == [208]
        assert e.interfaces == ["Vlan208"]

    def test_three_distinct_macs(self):
        with patch.object(self.c, "_snmpwalk", side_effect=_mock(
            ARP_MAC_LINES, ARP_TYPE_LINES, IF_NAME_LINES,
        )):
            entries = self.c.collect()

        macs = {e.mac_address for e in entries}
        assert len(entries) == 3
        assert "C0:EE:40:14:11:83" in macs
        assert "AA:BB:CC:DD:EE:FF" in macs
        assert "11:22:33:44:55:66" in macs

    def test_filters_type_other(self):
        """type=1 (other) must be excluded."""
        with patch.object(self.c, "_snmpwalk", side_effect=_mock(
            ["IP-MIB::ipNetToMediaPhysAddress.208.10.0.0.1 = Hex-STRING: AA BB CC DD EE FF"],
            ["IP-MIB::ipNetToMediaType.208.10.0.0.1 = INTEGER: 1"],
            ["IF-MIB::ifName.208 = STRING: Vlan208"],
        )):
            assert self.c.collect() == []

    def test_filters_type_invalid(self):
        """type=2 (invalid) must be excluded."""
        with patch.object(self.c, "_snmpwalk", side_effect=_mock(
            ["IP-MIB::ipNetToMediaPhysAddress.208.10.0.0.2 = Hex-STRING: AA BB CC DD EE FF"],
            ["IP-MIB::ipNetToMediaType.208.10.0.0.2 = INTEGER: 2"],
            ["IF-MIB::ifName.208 = STRING: Vlan208"],
        )):
            assert self.c.collect() == []

    def test_keeps_type_static(self):
        """type=4 (static) must be included."""
        with patch.object(self.c, "_snmpwalk", side_effect=_mock(
            ["IP-MIB::ipNetToMediaPhysAddress.208.10.0.0.1 = Hex-STRING: AA BB CC DD EE FF"],
            ["IP-MIB::ipNetToMediaType.208.10.0.0.1 = INTEGER: 4"],
            ["IF-MIB::ifName.208 = STRING: Vlan208"],
        )):
            assert len(self.c.collect()) == 1

    def test_missing_type_defaults_to_other_excluded(self):
        """No type entry for a key → defaults to 1 (other) → excluded."""
        with patch.object(self.c, "_snmpwalk", side_effect=_mock(
            ["IP-MIB::ipNetToMediaPhysAddress.208.10.0.0.1 = Hex-STRING: AA BB CC DD EE FF"],
            [],   # no type data at all
            ["IF-MIB::ifName.208 = STRING: Vlan208"],
        )):
            assert self.c.collect() == []

    def test_mixed_valid_and_invalid_types(self):
        """Only dynamic(3) and static(4) are returned; other(1) and invalid(2) are dropped."""
        with patch.object(self.c, "_snmpwalk", side_effect=_mock(
            [
                "IP-MIB::ipNetToMediaPhysAddress.100.10.0.1.1 = Hex-STRING: AA AA AA AA AA AA",
                "IP-MIB::ipNetToMediaPhysAddress.100.10.0.1.2 = Hex-STRING: BB BB BB BB BB BB",
                "IP-MIB::ipNetToMediaPhysAddress.100.10.0.1.3 = Hex-STRING: CC CC CC CC CC CC",
                "IP-MIB::ipNetToMediaPhysAddress.100.10.0.1.4 = Hex-STRING: DD DD DD DD DD DD",
            ],
            [
                "IP-MIB::ipNetToMediaType.100.10.0.1.1 = INTEGER: 3",  # dynamic  → keep
                "IP-MIB::ipNetToMediaType.100.10.0.1.2 = INTEGER: 2",  # invalid  → drop
                "IP-MIB::ipNetToMediaType.100.10.0.1.3 = INTEGER: 4",  # static   → keep
                "IP-MIB::ipNetToMediaType.100.10.0.1.4 = INTEGER: 1",  # other    → drop
            ],
            ["IF-MIB::ifName.100 = STRING: Vlan100"],
        )):
            entries = self.c.collect()

        macs = {e.mac_address for e in entries}
        assert len(entries) == 2
        assert "AA:AA:AA:AA:AA:AA" in macs
        assert "CC:CC:CC:CC:CC:CC" in macs
        assert "BB:BB:BB:BB:BB:BB" not in macs
        assert "DD:DD:DD:DD:DD:DD" not in macs

    def test_aggregates_same_mac_multiple_vlans(self):
        """Same MAC behind two VLAN SVIs → one ArpEntry with two IPs/VLANs/interfaces."""
        with patch.object(self.c, "_snmpwalk", side_effect=_mock(
            [
                "IP-MIB::ipNetToMediaPhysAddress.100.10.0.100.1 = Hex-STRING: AA BB CC DD EE FF",
                "IP-MIB::ipNetToMediaPhysAddress.200.10.0.200.1 = Hex-STRING: AA BB CC DD EE FF",
            ],
            [
                "IP-MIB::ipNetToMediaType.100.10.0.100.1 = INTEGER: 3",
                "IP-MIB::ipNetToMediaType.200.10.0.200.1 = INTEGER: 3",
            ],
            [
                "IF-MIB::ifName.100 = STRING: Vlan100",
                "IF-MIB::ifName.200 = STRING: Vlan200",
            ],
        )):
            entries = self.c.collect()

        assert len(entries) == 1
        e = entries[0]
        assert e.mac_address == "AA:BB:CC:DD:EE:FF"
        assert sorted(e.ip_addresses) == ["10.0.100.1", "10.0.200.1"]
        assert sorted(e.vlan_ids) == [100, 200]
        assert sorted(e.interfaces) == ["Vlan100", "Vlan200"]

    def test_network_loop_same_mac_same_vlan_different_ips(self):
        """Network loop: same MAC appears twice in the same VLAN with different IPs."""
        with patch.object(self.c, "_snmpwalk", side_effect=_mock(
            [
                "IP-MIB::ipNetToMediaPhysAddress.100.10.0.1.1 = Hex-STRING: AA BB CC DD EE FF",
                "IP-MIB::ipNetToMediaPhysAddress.100.10.0.1.2 = Hex-STRING: AA BB CC DD EE FF",
            ],
            [
                "IP-MIB::ipNetToMediaType.100.10.0.1.1 = INTEGER: 3",
                "IP-MIB::ipNetToMediaType.100.10.0.1.2 = INTEGER: 3",
            ],
            ["IF-MIB::ifName.100 = STRING: Vlan100"],
        )):
            entries = self.c.collect()

        assert len(entries) == 1
        e = entries[0]
        assert sorted(e.ip_addresses) == ["10.0.1.1", "10.0.1.2"]
        assert e.vlan_ids == [100]       # same VLAN — deduplicated
        assert e.interfaces == ["Vlan100"]  # same interface — deduplicated

    def test_returns_sorted_lists(self):
        """ip_addresses, vlan_ids, interfaces are sorted regardless of walk order."""
        with patch.object(self.c, "_snmpwalk", side_effect=_mock(
            [
                "IP-MIB::ipNetToMediaPhysAddress.300.10.0.30.1 = Hex-STRING: AA BB CC DD EE FF",
                "IP-MIB::ipNetToMediaPhysAddress.100.10.0.10.1 = Hex-STRING: AA BB CC DD EE FF",
            ],
            [
                "IP-MIB::ipNetToMediaType.300.10.0.30.1 = INTEGER: 3",
                "IP-MIB::ipNetToMediaType.100.10.0.10.1 = INTEGER: 3",
            ],
            [
                "IF-MIB::ifName.300 = STRING: Vlan300",
                "IF-MIB::ifName.100 = STRING: Vlan100",
            ],
        )):
            entries = self.c.collect()

        e = entries[0]
        assert e.ip_addresses == sorted(e.ip_addresses)
        assert e.vlan_ids == sorted(e.vlan_ids)
        assert e.interfaces == sorted(e.interfaces)

    def test_physical_iface_no_vlan_id(self):
        """MAC on a physical (non-VLAN) interface → vlan_ids is empty."""
        with patch.object(self.c, "_snmpwalk", side_effect=_mock(
            ["IP-MIB::ipNetToMediaPhysAddress.1.10.0.0.1 = Hex-STRING: AA BB CC DD EE FF"],
            ["IP-MIB::ipNetToMediaType.1.10.0.0.1 = INTEGER: 3"],
            ["IF-MIB::ifName.1 = STRING: GigabitEthernet0/0"],
        )):
            entries = self.c.collect()

        assert len(entries) == 1
        assert entries[0].vlan_ids == []
        assert entries[0].interfaces == ["GigabitEthernet0/0"]

    def test_missing_ifname_uses_fallback(self):
        """ifindex not present in ifName walk → interface named 'ifindex-N'."""
        with patch.object(self.c, "_snmpwalk", side_effect=_mock(
            ["IP-MIB::ipNetToMediaPhysAddress.999.10.0.0.1 = Hex-STRING: AA BB CC DD EE FF"],
            ["IP-MIB::ipNetToMediaType.999.10.0.0.1 = INTEGER: 3"],
            [],  # empty ifName response
        )):
            entries = self.c.collect()

        assert entries[0].interfaces == ["ifindex-999"]
        assert entries[0].vlan_ids == []

    def test_empty_snmp_responses(self):
        """All three walks return nothing → empty result."""
        with patch.object(self.c, "_snmpwalk", side_effect=[[], [], []]):
            assert self.c.collect() == []

    def test_returns_list_of_arp_entry(self):
        """Return type is list[ArpEntry]."""
        with patch.object(self.c, "_snmpwalk", side_effect=_mock(
            ARP_MAC_LINES, ARP_TYPE_LINES, IF_NAME_LINES,
        )):
            entries = self.c.collect()

        assert isinstance(entries, list)
        assert all(isinstance(e, ArpEntry) for e in entries)


# ------------------------------------------------------------------
# collect_async()
# ------------------------------------------------------------------

class TestCollectAsync:
    @pytest.mark.asyncio
    async def test_async_returns_same_entries_as_sync(self):
        c = _collector()
        with patch.object(c, "_snmpwalk", side_effect=_mock(
            ["IP-MIB::ipNetToMediaPhysAddress.208.10.0.208.10 = Hex-STRING: C0 EE 40 14 11 83"],
            ["IP-MIB::ipNetToMediaType.208.10.0.208.10 = INTEGER: 3"],
            ["IF-MIB::ifName.208 = STRING: Vlan208"],
        )):
            entries = await c.collect_async()

        assert len(entries) == 1
        assert entries[0].mac_address == "C0:EE:40:14:11:83"
        assert entries[0].vlan_ids == [208]

    @pytest.mark.asyncio
    async def test_async_empty(self):
        c = _collector()
        with patch.object(c, "_snmpwalk", side_effect=[[], [], []]):
            assert await c.collect_async() == []


# ------------------------------------------------------------------
# Constructor
# ------------------------------------------------------------------

class TestArpCollectorInit:
    def test_community_from_arg(self):
        c = ArpCollector("1.2.3.4", community="mysecret")
        assert c.community == "mysecret"

    def test_community_from_env(self, monkeypatch):
        monkeypatch.setenv("SNMP_COMMUNITY", "envcomm")
        c = ArpCollector("1.2.3.4")
        assert c.community == "envcomm"

    def test_arg_takes_precedence_over_env(self, monkeypatch):
        monkeypatch.setenv("SNMP_COMMUNITY", "envcomm")
        c = ArpCollector("1.2.3.4", community="argcomm")
        assert c.community == "argcomm"

    def test_default_timeout(self):
        assert ArpCollector("1.2.3.4", community="x").timeout == 30

    def test_custom_timeout(self):
        assert ArpCollector("1.2.3.4", community="x", timeout=60).timeout == 60

    def test_ip_stored(self):
        c = ArpCollector("192.168.1.1", community="pub")
        assert c.ip == "192.168.1.1"
