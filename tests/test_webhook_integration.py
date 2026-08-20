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
    "indicator_type": "ip",
    "indicator_value": "9.9.9.9",
    "message": "scan detected",
}

SECRET = "test-secret-for-ci"


class TestWebhookIntegration(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.app = create_app({
            "DATABASE_PATH": os.path.join(self.tmpdir, "test.db"),
            "WEBHOOK_SHARED_SECRET": SECRET,
            "TESTING": True,
        })
        self.client = self.app.test_client()

    def post_alert(self, payload, secret=SECRET):
        headers = {"Content-Type": "application/json"}
        if secret is not None:
            headers["X-Webhook-Secret"] = secret
        return self.client.post("/webhook/alert", json=payload, headers=headers)

    def test_missing_secret_is_rejected(self):
        resp = self.post_alert(VALID_ALERT, secret=None)
        self.assertEqual(resp.status_code, 401)

    def test_wrong_secret_is_rejected(self):
        resp = self.post_alert(VALID_ALERT, secret="wrong")
        self.assertEqual(resp.status_code, 401)

    def test_valid_alert_is_accepted_and_routed(self):
        resp = self.post_alert(VALID_ALERT)
        self.assertEqual(resp.status_code, 201)
        body = resp.get_json()
        self.assertIn(body["destination"], {"slack", "jira", "dropped"})

    def test_missing_required_field_is_rejected(self):
        bad = {k: v for k, v in VALID_ALERT.items() if k != "asset_id"}
        resp = self.post_alert(bad)
        self.assertEqual(resp.status_code, 400)

    def test_invalid_severity_is_rejected(self):
        bad = {**VALID_ALERT, "severity": "apocalyptic"}
        resp = self.post_alert(bad)
        self.assertEqual(resp.status_code, 400)

    def test_repeat_alert_within_window_is_deduped(self):
        first = self.post_alert(VALID_ALERT)
        second = self.post_alert(VALID_ALERT)
        self.assertEqual(first.get_json()["status"], "routed")
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second.get_json()["status"], "deduped")

    def test_index_page_renders(self):
        self.post_alert(VALID_ALERT)
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Recent alerts", resp.data)

    def test_demo_send_hits_real_pipeline(self):
        resp = self.client.post("/demo/send")
        self.assertEqual(resp.status_code, 302)  # redirects back to index
        index = self.client.get("/")
        self.assertIn(b"row-", index.data)  # at least one alert row rendered


if __name__ == "__main__":
    unittest.main()
