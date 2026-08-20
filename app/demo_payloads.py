"""Data for demo-mode alert sending: a guided default sequence (zero-config quick
send), named templates the UI offers as presets, and a component pool the UI samples
from for "random" test alerts. The actual random pick and any user edits happen
client-side in the browser — this module is the single source of truth for the values.
"""
from __future__ import annotations

TEMPLATES = [
    {
        "id": "failed-login",
        "label": "Failed login (low)",
        "payload": {
            "source": "edr-console",
            "alert_type": "failed_login",
            "severity": "low",
            "asset_id": "ws-0042-marketing",
            "asset_criticality": "low",
            "indicator_type": None,
            "indicator_value": None,
            "message": "3 failed login attempts, account locked automatically",
        },
    },
    {
        "id": "port-scan",
        "label": "Port scan (medium, malicious IP)",
        "payload": {
            "source": "edr-console",
            "alert_type": "port_scan_detected",
            "severity": "medium",
            "asset_id": "srv-web-03",
            "asset_criticality": "medium",
            "indicator_type": "ip",
            "indicator_value": "185.220.101.45",
            "message": "internal port scan originating from workstation subnet",
        },
    },
    {
        "id": "malware",
        "label": "Malware detected (critical)",
        "payload": {
            "source": "edr-console",
            "alert_type": "malware_detected",
            "severity": "critical",
            "asset_id": "srv-db-prod-01",
            "asset_criticality": "high",
            "indicator_type": "hash",
            "indicator_value": "e99a18c428cb38d5f260853678922e03",
            "message": "known ransomware signature quarantined on production database host",
        },
    },
]

# Guided sequence for the zero-config "quick send" (no fields submitted): each
# template once, then a repeat of the port-scan alert to demonstrate dedup.
DEMO_SEQUENCE = [t["payload"] for t in TEMPLATES] + [TEMPLATES[1]["payload"]]

RANDOM_POOL = {
    "source": ["edr-console", "waf", "cloudtrail", "okta", "endpoint-agent"],
    "alert_type": [
        "failed_login", "port_scan_detected", "malware_detected", "suspicious_process",
        "data_exfil_attempt", "privilege_escalation", "impossible_travel",
    ],
    "severity": ["low", "medium", "high", "critical"],
    "asset_id": ["ws-0091-sales", "srv-web-04", "srv-db-prod-02", "ws-0210-eng", "srv-auth-01"],
    "asset_criticality": ["low", "medium", "high"],
    "indicator": [
        {"indicator_type": None, "indicator_value": None},
        {"indicator_type": "ip", "indicator_value": "185.220.101.45"},
        {"indicator_type": "ip", "indicator_value": "45.155.205.28"},
        {"indicator_type": "hash", "indicator_value": "e99a18c428cb38d5f260853678922e03"},
        {"indicator_type": "hash", "indicator_value": "5f4dcc3b5aa765d61d8327deb882cf99"},
    ],
    "message": [
        "anomalous outbound traffic volume detected",
        "multiple failed auth attempts from new geography",
        "known-bad hash matched on endpoint scan",
        "unexpected process spawned by office document",
        "port sweep detected against internal subnet",
    ],
}


def next_payload(counter: int) -> dict:
    return DEMO_SEQUENCE[counter % len(DEMO_SEQUENCE)]
