"""Enrichment providers.

Design goal: the app must work from a cold clone with zero API keys (demo mode), but
upgrade automatically to a real reputation lookup the moment a key is configured.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, asdict
from typing import Optional

import requests


@dataclass
class EnrichmentResult:
    provider: str
    indicator_type: Optional[str]
    indicator_value: Optional[str]
    reputation_score: int  # 0 (clean) - 100 (malicious)
    malicious: bool
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


class MockReputationProvider:
    """Deterministic, dependency-free stand-in for a real threat-intel lookup.

    Deterministic (hash-based) rather than random so the same indicator always scores
    the same way in the demo — makes the routing decisions reproducible when you show
    this live.
    """

    name = "mock"

    def lookup(self, indicator_type: Optional[str], indicator_value: Optional[str]) -> EnrichmentResult:
        if not indicator_value:
            return EnrichmentResult(
                provider=self.name,
                indicator_type=indicator_type,
                indicator_value=indicator_value,
                reputation_score=0,
                malicious=False,
                detail="no indicator supplied, nothing to look up",
            )
        digest = hashlib.sha256(indicator_value.encode("utf-8")).hexdigest()
        score = int(digest[:2], 16) % 101  # 0-100, stable per indicator
        malicious = score >= 70
        detail = (
            f"mock lookup for {indicator_type or 'indicator'} '{indicator_value}': "
            f"reputation score {score}/100 (no ABUSEIPDB_API_KEY configured — "
            f"set one to use live reputation data)"
        )
        return EnrichmentResult(
            provider=self.name,
            indicator_type=indicator_type,
            indicator_value=indicator_value,
            reputation_score=score,
            malicious=malicious,
            detail=detail,
        )


class AbuseIPDBProvider:
    """Real lookup against AbuseIPDB. Only used for indicator_type == 'ip'."""

    name = "abuseipdb"
    ENDPOINT = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def lookup(self, indicator_type: Optional[str], indicator_value: Optional[str]) -> EnrichmentResult:
        if indicator_type != "ip" or not indicator_value:
            # Fall back to the mock for non-IP indicators — AbuseIPDB only does IPs.
            return MockReputationProvider().lookup(indicator_type, indicator_value)
        try:
            resp = requests.get(
                self.ENDPOINT,
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": indicator_value, "maxAgeInDays": 90},
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            score = int(data.get("abuseConfidenceScore", 0))
            malicious = score >= 50
            detail = (
                f"AbuseIPDB: {indicator_value} — confidence score {score}/100, "
                f"{data.get('totalReports', 0)} reports, "
                f"country={data.get('countryCode', 'unknown')}"
            )
            return EnrichmentResult(
                provider=self.name,
                indicator_type=indicator_type,
                indicator_value=indicator_value,
                reputation_score=score,
                malicious=malicious,
                detail=detail,
            )
        except requests.RequestException as exc:
            # Never let a third-party outage break alert processing — degrade to mock.
            fallback = MockReputationProvider().lookup(indicator_type, indicator_value)
            fallback.detail = f"AbuseIPDB lookup failed ({exc}); fell back to mock. {fallback.detail}"
            return fallback


def get_provider(api_key: str):
    if api_key:
        return AbuseIPDBProvider(api_key)
    return MockReputationProvider()


def enrich(indicator_type: Optional[str], indicator_value: Optional[str], api_key: str = "") -> EnrichmentResult:
    provider = get_provider(api_key)
    return provider.lookup(indicator_type, indicator_value)
