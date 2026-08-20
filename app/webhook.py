from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request

from . import dedup, enrichment, routing
from .db import get_db

bp = Blueprint("webhook", __name__)

REQUIRED_FIELDS = ["source", "alert_type", "severity", "asset_id"]
VALID_SEVERITY = {"low", "medium", "high", "critical"}


class ValidationError(ValueError):
    pass


def validate_payload(payload: dict) -> None:
    if not payload or not isinstance(payload, dict):
        raise ValidationError("request body must be a JSON object")
    missing = [f for f in REQUIRED_FIELDS if not payload.get(f)]
    if missing:
        raise ValidationError(f"missing required field(s): {', '.join(missing)}")
    severity = str(payload["severity"]).lower()
    if severity not in VALID_SEVERITY:
        raise ValidationError(f"severity must be one of {sorted(VALID_SEVERITY)}")


def process_alert(payload: dict, raw_body: str = "") -> dict:
    """Core pipeline: dedup -> enrich -> route -> persist. Used by both the real webhook
    and the demo button, so a click on the demo button exercises the exact same code path
    a real EDR integration would.
    """
    validate_payload(payload)

    config = current_app.config
    source = str(payload["source"])
    alert_type = str(payload["alert_type"])
    severity = str(payload["severity"]).lower()
    asset_id = str(payload["asset_id"])
    asset_criticality = str(payload.get("asset_criticality", "medium")).lower()
    indicator_type = payload.get("indicator_type")
    indicator_value = payload.get("indicator_value")
    message = str(payload.get("message", ""))

    alert_id = str(uuid.uuid4())
    received_at = datetime.now(timezone.utc).isoformat()
    dedup_hash = dedup.compute_dedup_hash(source, alert_type, asset_id, indicator_value, message)
    raw_body = raw_body or json.dumps(payload)

    db = get_db()

    duplicate_of = dedup.find_recent_duplicate(dedup_hash, config["DEDUP_WINDOW_MINUTES"])
    if duplicate_of:
        db.execute(
            """
            INSERT INTO alerts (id, received_at, source, alert_type, severity, asset_id,
                asset_criticality, indicator_type, indicator_value, message, raw_payload,
                dedup_hash, dedup_of, enrichment_json, routing_decision, routing_detail, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id, received_at, source, alert_type, severity, asset_id, asset_criticality,
                indicator_type, indicator_value, message, raw_body,
                dedup_hash, duplicate_of, None, "deduped",
                f"duplicate of alert {duplicate_of} within {config['DEDUP_WINDOW_MINUTES']}m window",
                "deduped",
            ),
        )
        db.commit()
        return {"id": alert_id, "status": "deduped", "duplicate_of": duplicate_of}

    enrichment_result = enrichment.enrich(indicator_type, indicator_value, config["ABUSEIPDB_API_KEY"])
    decision = routing.decide(severity, asset_criticality, enrichment_result.malicious)

    if decision.destination == "slack":
        summary = f"[{severity.upper()}] {alert_type} on {asset_id} — {message or 'no details provided'}"
        detail = routing.send_to_slack(config["SLACK_WEBHOOK_URL"], summary)
    elif decision.destination == "jira":
        summary = f"[{severity.upper()}] {alert_type} on {asset_id}"
        description = (
            f"{message}\n\nSource: {source}\nAsset criticality: {asset_criticality}\n"
            f"Enrichment: {enrichment_result.detail}"
        )
        detail = routing.create_jira_ticket(
            config["JIRA_BASE_URL"], config["JIRA_EMAIL"],
            config["JIRA_API_TOKEN"], config["JIRA_PROJECT_KEY"],
            summary, description,
        )
    else:
        detail = decision.reason

    status = "dropped" if decision.destination == "dropped" else "routed"

    db.execute(
        """
        INSERT INTO alerts (id, received_at, source, alert_type, severity, asset_id,
            asset_criticality, indicator_type, indicator_value, message, raw_payload,
            dedup_hash, dedup_of, enrichment_json, routing_decision, routing_detail, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert_id, received_at, source, alert_type, severity, asset_id, asset_criticality,
            indicator_type, indicator_value, message, raw_body,
            dedup_hash, None,
            json.dumps(enrichment_result.to_dict()),
            decision.destination, detail, status,
        ),
    )
    db.commit()

    return {
        "id": alert_id,
        "status": status,
        "destination": decision.destination,
        "routing_reason": decision.reason,
        "enrichment": enrichment_result.to_dict(),
    }


@bp.route("/webhook/alert", methods=["POST"])
def receive_alert():
    provided_secret = request.headers.get("X-Webhook-Secret", "")
    if provided_secret != current_app.config["WEBHOOK_SHARED_SECRET"]:
        return jsonify({"error": "invalid or missing X-Webhook-Secret header"}), 401

    payload = request.get_json(silent=True)
    try:
        validate_payload(payload)
        result = process_alert(payload, raw_body=request.get_data(as_text=True))
    except ValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    status_code = 201 if result["status"] != "deduped" else 200
    return jsonify(result), status_code
