import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app

VALID_ALERT = {
    "source": "edr-console",
    "alert_type": "port_scan_detected",
    "severity": "medium",
    "asset_id": "srv-web-03",
    "asset_criticality": "medium",
}

SECRET = "test-secret-for-ci"


class TestRateLimit(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.app = create_app({
            "DATABASE_PATH": os.path.join(self.tmpdir, "test.db"),
            "WEBHOOK_SHARED_SECRET": SECRET,
            "TESTING": True,
        })
        self.client = self.app.test_client()

    def test_webhook_rate_limit_returns_429_after_threshold(self):
        headers = {"Content-Type": "application/json", "X-Webhook-Secret": SECRET}
        statuses = [
            self.client.post("/webhook/alert", json=VALID_ALERT, headers=headers).status_code
            for _ in range(35)
        ]
        self.assertIn(429, statuses)

    def test_rate_limit_is_scoped_per_endpoint(self):
        headers = {"Content-Type": "application/json", "X-Webhook-Secret": SECRET}
        for _ in range(30):
            self.client.post("/webhook/alert", json=VALID_ALERT, headers=headers)
        # a saturated webhook limit must not block the unrelated demo endpoint
        resp = self.client.post("/demo/send")
        self.assertEqual(resp.status_code, 302)


if __name__ == "__main__":
    unittest.main()
