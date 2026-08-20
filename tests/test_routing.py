import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import routing


class TestRoutingDecisions(unittest.TestCase):
    def test_low_severity_low_criticality_is_dropped(self):
        decision = routing.decide("low", "low", malicious_indicator=False)
        self.assertEqual(decision.destination, "dropped")

    def test_medium_severity_medium_criticality_reaches_slack(self):
        decision = routing.decide("medium", "medium", malicious_indicator=False)
        self.assertEqual(decision.destination, "slack")

    def test_critical_severity_high_criticality_reaches_jira(self):
        decision = routing.decide("critical", "high", malicious_indicator=False)
        self.assertEqual(decision.destination, "jira")

    def test_malicious_indicator_bumps_a_borderline_alert_up(self):
        without = routing.decide("low", "medium", malicious_indicator=False)
        with_hit = routing.decide("low", "medium", malicious_indicator=True)
        self.assertGreaterEqual(with_hit.combined_score, without.combined_score + 2)

    def test_unknown_severity_defaults_to_lowest_score(self):
        decision = routing.decide("not-a-real-severity", "low", malicious_indicator=False)
        self.assertEqual(decision.destination, "dropped")

    def test_slack_mock_fallback_when_no_webhook_configured(self):
        detail = routing.send_to_slack("", "test summary")
        self.assertIn("mock", detail)
        self.assertIn("test summary", detail)

    def test_jira_mock_fallback_when_not_configured(self):
        detail = routing.create_jira_ticket("", "", "", "", "test summary", "desc")
        self.assertIn("mock", detail)


if __name__ == "__main__":
    unittest.main()
