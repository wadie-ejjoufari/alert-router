import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import enrichment


class TestMockEnrichment(unittest.TestCase):
    def test_same_indicator_always_scores_the_same(self):
        r1 = enrichment.enrich("ip", "1.2.3.4")
        r2 = enrichment.enrich("ip", "1.2.3.4")
        self.assertEqual(r1.reputation_score, r2.reputation_score)
        self.assertEqual(r1.malicious, r2.malicious)

    def test_different_indicators_can_score_differently(self):
        scores = {enrichment.enrich("ip", f"10.0.0.{i}").reputation_score for i in range(20)}
        self.assertGreater(len(scores), 1, "20 different IPs should not all hash to one score")

    def test_no_indicator_is_never_malicious(self):
        result = enrichment.enrich(None, None)
        self.assertFalse(result.malicious)
        self.assertEqual(result.reputation_score, 0)

    def test_missing_api_key_uses_mock_provider(self):
        result = enrichment.enrich("ip", "8.8.8.8", api_key="")
        self.assertEqual(result.provider, "mock")

    def test_api_key_present_selects_abuseipdb_provider_for_ip(self):
        provider = enrichment.get_provider("fake-key")
        self.assertIsInstance(provider, enrichment.AbuseIPDBProvider)

    def test_abuseipdb_falls_back_to_mock_for_non_ip_indicators(self):
        provider = enrichment.AbuseIPDBProvider("fake-key")
        result = provider.lookup("hash", "deadbeef")
        self.assertEqual(result.provider, "mock")


if __name__ == "__main__":
    unittest.main()
