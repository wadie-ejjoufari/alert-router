"""Canned EDR-shaped payloads for demo mode.

Cycled in order so a cold visitor clicking "Send test alert" repeatedly sees, in
sequence: something that gets dropped, something that reaches Slack, something that
opens a Jira ticket, and a repeat that demonstrates dedup. That sequence is more
convincing than random payloads because it tells a story about what the router does.
"""
from __future__ import annotations

DEMO_SEQUENCE = [
    {
        "source": "edr-console",
        "alert_type": "failed_login",
        "severity": "low",
        "asset_id": "ws-0042-marketing",
        "asset_criticality": "low",
        "message": "3 failed login attempts, account locked automatically",
    },
    {
        "source": "edr-console",
        "alert_type": "port_scan_detected",
        "severity": "medium",
        "asset_id": "srv-web-03",
        "asset_criticality": "medium",
        "indicator_type": "ip",
        "indicator_value": "185.220.101.45",
        "message": "internal port scan originating from workstation subnet",
    },
    {
        "source": "edr-console",
        "alert_type": "malware_detected",
        "severity": "critical",
        "asset_id": "srv-db-prod-01",
        "asset_criticality": "high",
        "indicator_type": "hash",
        "indicator_value": "e99a18c428cb38d5f260853678922e03",
        "message": "known ransomware signature quarantined on production database host",
    },
    {
        # Same shape as the port-scan alert above -> demonstrates dedup when sent within
        # the dedup window.
        "source": "edr-console",
        "alert_type": "port_scan_detected",
        "severity": "medium",
        "asset_id": "srv-web-03",
        "asset_criticality": "medium",
        "indicator_type": "ip",
        "indicator_value": "185.220.101.45",
        "message": "internal port scan originating from workstation subnet",
    },
]


def next_payload(counter: int) -> dict:
    return DEMO_SEQUENCE[counter % len(DEMO_SEQUENCE)]
