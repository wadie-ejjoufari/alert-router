import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import dedup


class TestDedupHash(unittest.TestCase):
    def test_identical_alerts_produce_identical_hash(self):
        h1 = dedup.compute_dedup_hash("edr", "port_scan", "srv-1", "1.2.3.4", "scan detected")
        h2 = dedup.compute_dedup_hash("edr", "port_scan", "srv-1", "1.2.3.4", "scan detected")
        self.assertEqual(h1, h2)

    def test_different_asset_produces_different_hash(self):
        h1 = dedup.compute_dedup_hash("edr", "port_scan", "srv-1", "1.2.3.4", "scan detected")
        h2 = dedup.compute_dedup_hash("edr", "port_scan", "srv-2", "1.2.3.4", "scan detected")
        self.assertNotEqual(h1, h2)

    def test_missing_indicator_does_not_crash(self):
        h = dedup.compute_dedup_hash("edr", "failed_login", "ws-1", None, "3 attempts")
        self.assertIsInstance(h, str)
        self.assertEqual(len(h), 64)  # sha256 hex digest length


if __name__ == "__main__":
    unittest.main()
