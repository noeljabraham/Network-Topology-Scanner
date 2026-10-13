import ipaddress
import tempfile
import unittest
from pathlib import Path

from app.models import Device
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


if __name__ == "__main__":
    unittest.main()
