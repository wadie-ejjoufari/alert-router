from __future__ import annotations

import json

from flask import Blueprint, current_app, redirect, render_template, request, url_for

from .db import get_db
from .demo_payloads import RANDOM_POOL, TEMPLATES, next_payload
from .ratelimit import rate_limit
from .webhook import ValidationError, process_alert

bp = Blueprint("views", __name__)

_demo_counter = {"n": 0}  # in-memory, single-process — fine for a demo, not for prod


def _render_index(error: str | None = None, form_values: dict | None = None):
    db = get_db()
    limit = current_app.config["RECENT_ALERTS_LIMIT"]
    rows = db.execute(
        "SELECT * FROM alerts ORDER BY received_at DESC LIMIT ?", (limit,)
    ).fetchall()

    alerts = []
    for row in rows:
        enrichment = json.loads(row["enrichment_json"]) if row["enrichment_json"] else None
        try:
            raw_pretty = json.dumps(json.loads(row["raw_payload"]), indent=2)
        except (TypeError, ValueError):
            raw_pretty = row["raw_payload"]
        alerts.append({**dict(row), "enrichment": enrichment, "raw_pretty": raw_pretty})

    total = db.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
    routed = db.execute("SELECT COUNT(*) AS c FROM alerts WHERE status='routed'").fetchone()["c"]
    dropped = db.execute("SELECT COUNT(*) AS c FROM alerts WHERE status='dropped'").fetchone()["c"]
    deduped = db.execute("SELECT COUNT(*) AS c FROM alerts WHERE status='deduped'").fetchone()["c"]

    return render_template(
        "index.html",
        alerts=alerts,
        stats={"total": total, "routed": routed, "dropped": dropped, "deduped": deduped},
        templates=TEMPLATES,
        random_pool=RANDOM_POOL,
        error=error,
        form_values=form_values or {},
    )


@bp.route("/")
def index():
    return _render_index()


@bp.route("/demo/send", methods=["POST"])
@rate_limit(max_requests=20, window_seconds=60)
def demo_send():
    """Runs an alert through the exact same pipeline a real EDR webhook call would use —
    in-process, not a real HTTP round trip, so the demo form works identically under
    `flask run` and behind a load balancer with no self-referential network call.

    A plain POST with no fields (the original single-button demo) cycles through a
    guided story sequence. Once the form on the page submits actual field values —
    whether picked from a template, randomized, or hand-edited, the browser has already
    reconciled all of that into one set of fields by the time it posts — those values
    are used directly.
    """
    if "mode" in request.form:
        payload = {
            "source": request.form.get("source", "").strip(),
            "alert_type": request.form.get("alert_type", "").strip(),
            "severity": request.form.get("severity", "low").strip().lower(),
            "asset_id": request.form.get("asset_id", "").strip(),
            "asset_criticality": request.form.get("asset_criticality", "medium").strip().lower(),
            "indicator_type": request.form.get("indicator_type", "").strip() or None,
            "indicator_value": request.form.get("indicator_value", "").strip() or None,
            "message": request.form.get("message", "").strip(),
        }
    else:
        payload = next_payload(_demo_counter["n"])
        _demo_counter["n"] += 1

    try:
        process_alert(payload)
    except ValidationError as exc:
        return _render_index(error=str(exc), form_values=payload), 400

    return redirect(url_for("views.index"))
