import ipaddress
import tempfile
import unittest
from pathlib import Path

from app.models import Device
from app.nmap_scanner import parse_xml
from app.scanner import network_info
from app.store import DeviceStore


class StoreTests(unittest.TestCase):
    def test_upsert_preserves_first_seen_and_updates_status(self):
        with tempfile.TemporaryDirectory() as directory:
            store = DeviceStore(Path(directory) / "test.db")
            store.upsert(Device(ip="192.168.1.8", hostname="first", first_seen="one", last_seen="one"))
            store.upsert(Device(ip="192.168.1.8", hostname="second", first_seen="two", last_seen="two"))
            result = store.all()[0]
            self.assertEqual(result["first_seen"], "one")
            self.assertEqual(result["last_seen"], "two")
            self.assertEqual(result["hostname"], "second")

    def test_missing_devices_are_marked_offline(self):
        with tempfile.TemporaryDirectory() as directory:
            store = DeviceStore(Path(directory) / "test.db")
            store.upsert(Device(ip="192.168.1.8"))
            store.upsert(Device(ip="192.168.1.9"))
            store.mark_missing_offline({"192.168.1.8"})
            states = {item["ip"]: item["state"] for item in store.all()}
            self.assertEqual(states["192.168.1.8"], "online")
            self.assertEqual(states["192.168.1.9"], "offline")


class ScannerSafetyTests(unittest.TestCase):
    def test_rejects_scan_ranges_larger_than_slash_22(self):
        with self.assertRaises(ValueError):
            network_info("10.0.0.0/16")

    def test_accepts_bounded_range(self):
        info = network_info("192.168.10.0/24")
        self.assertEqual(info.network, ipaddress.ip_network("192.168.10.0/24"))


class NmapParserTests(unittest.TestCase):
    def test_parses_identity_services_and_os(self):
        xml = """<?xml version="1.0"?>
        <nmaprun><host><status state="up"/>
          <address addr="192.168.1.1" addrtype="ipv4"/>
          <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Example Networks"/>
          <hostnames><hostname name="router.local"/></hostnames>
          <ports><port protocol="tcp" portid="443"><state state="open"/>
            <service name="https" product="Example UI" version="1.2"/>
          </port></ports>
          <os><osmatch name="Linux 5.x" accuracy="96"/></os>
        </host></nmaprun>"""
        device = parse_xml(xml, gateway="192.168.1.1")[0]
        self.assertEqual(device.role, "gateway")
        self.assertEqual(device.vendor, "Example Networks")
        self.assertEqual(device.open_ports, [443])
        self.assertEqual(device.services[0].product, "Example UI")
        self.assertEqual(device.os_accuracy, 96)

    def test_ignores_down_hosts(self):
        xml = '<nmaprun><host><status state="down"/><address addr="192.168.1.8" addrtype="ipv4"/></host></nmaprun>'
        self.assertEqual(parse_xml(xml), [])

    def test_ignores_pn_targets_without_response_evidence(self):
        xml = """<nmaprun><host><status state="up" reason="user-set"/>
        <address addr="192.168.1.99" addrtype="ipv4"/>
        <ports><extraports state="filtered" count="100"/></ports></host></nmaprun>"""
        self.assertEqual(parse_xml(xml), [])

    def test_accepts_pn_target_with_closed_port_evidence(self):
        xml = """<nmaprun><host><status state="up" reason="user-set"/>
        <address addr="192.168.1.9" addrtype="ipv4"/>
        <ports><extraports state="closed" count="100"/></ports></host></nmaprun>"""
        self.assertEqual(parse_xml(xml)[0].ip, "192.168.1.9")


if __name__ == "__main__":
    unittest.main()
