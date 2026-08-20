"""Rule-based routing: severity + asset criticality + enrichment -> destination.

Scope, deliberately: two real destinations (Slack, Jira), everything below the Slack
threshold is dropped (logged, not paged — that's the point of a router: most alerts
should NOT reach a human). No multi-tenancy, no per-client rule configuration.
"""
from __future__ import annotations

from dataclasses import dataclass

import requests

SEVERITY_SCORE = {"low": 1, "medium": 2, "high": 3, "critical": 4}
CRITICALITY_SCORE = {"low": 1, "medium": 2, "high": 3}

# combined = severity_score * criticality_score, range 1-12
JIRA_THRESHOLD = 9   # e.g. critical severity x high-criticality asset, or high x high w/ malicious indicator
SLACK_THRESHOLD = 4  # e.g. medium severity x medium-criticality asset


@dataclass
class RoutingDecision:
    destination: str  # "jira" | "slack" | "dropped"
    combined_score: int
    reason: str
    detail: str = ""


def score(severity: str, asset_criticality: str, malicious_indicator: bool) -> int:
    s = SEVERITY_SCORE.get(severity.lower(), 1)
    c = CRITICALITY_SCORE.get(asset_criticality.lower(), 1)
    combined = s * c
    if malicious_indicator:
        combined += 2  # a hit against threat intel bumps priority regardless of stated severity
    return combined


def decide(severity: str, asset_criticality: str, malicious_indicator: bool) -> RoutingDecision:
    combined = score(severity, asset_criticality, malicious_indicator)
    if combined >= JIRA_THRESHOLD:
        return RoutingDecision(
            destination="jira",
            combined_score=combined,
            reason=f"score {combined} >= {JIRA_THRESHOLD} (Jira threshold)",
        )
    if combined >= SLACK_THRESHOLD:
        return RoutingDecision(
            destination="slack",
            combined_score=combined,
            reason=f"score {combined} >= {SLACK_THRESHOLD} (Slack threshold)",
        )
    return RoutingDecision(
        destination="dropped",
        combined_score=combined,
        reason=f"score {combined} < {SLACK_THRESHOLD} (below Slack threshold) — logged, no one paged",
    )


def send_to_slack(webhook_url: str, alert_summary: str) -> str:
    if not webhook_url:
        return f"[mock: no SLACK_WEBHOOK_URL configured] would post: {alert_summary}"
    try:
        resp = requests.post(webhook_url, json={"text": alert_summary}, timeout=5)
        resp.raise_for_status()
        return "posted to Slack"
    except requests.RequestException as exc:
        return f"[error posting to Slack: {exc}] would post: {alert_summary}"


def create_jira_ticket(base_url: str, email: str, api_token: str, project_key: str, summary: str, description: str) -> str:
    if not (base_url and email and api_token and project_key):
        return f"[mock: Jira not configured] would open ticket: {summary}"
    try:
        resp = requests.post(
            f"{base_url.rstrip('/')}/rest/api/3/issue",
            auth=(email, api_token),
            json={
                "fields": {
                    "project": {"key": project_key},
                    "summary": summary,
                    "description": {
                        "type": "doc",
                        "version": 1,
                        "content": [{"type": "paragraph", "content": [{"type": "text", "text": description}]}],
                    },
                    "issuetype": {"name": "Bug"},
                }
            },
            timeout=5,
        )
        resp.raise_for_status()
        key = resp.json().get("key", "unknown")
        return f"created Jira ticket {key}"
    except requests.RequestException as exc:
        return f"[error creating Jira ticket: {exc}] would open ticket: {summary}"
