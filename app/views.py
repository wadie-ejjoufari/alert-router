from __future__ import annotations

import json

from flask import Blueprint, current_app, redirect, render_template, url_for

from .db import get_db
from .demo_payloads import next_payload
from .webhook import process_alert

bp = Blueprint("views", __name__)

_demo_counter = {"n": 0}  # in-memory, single-process — fine for a demo, not for prod


@bp.route("/")
def index():
    db = get_db()
    limit = current_app.config["RECENT_ALERTS_LIMIT"]
    rows = db.execute(
        "SELECT * FROM alerts ORDER BY received_at DESC LIMIT ?", (limit,)
    ).fetchall()

    alerts = []
    for row in rows:
        enrichment = json.loads(row["enrichment_json"]) if row["enrichment_json"] else None
        alerts.append({**dict(row), "enrichment": enrichment})

    total = db.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
    routed = db.execute("SELECT COUNT(*) AS c FROM alerts WHERE status='routed'").fetchone()["c"]
    dropped = db.execute("SELECT COUNT(*) AS c FROM alerts WHERE status='dropped'").fetchone()["c"]
    deduped = db.execute("SELECT COUNT(*) AS c FROM alerts WHERE status='deduped'").fetchone()["c"]

    return render_template(
        "index.html",
        alerts=alerts,
        stats={"total": total, "routed": routed, "dropped": dropped, "deduped": deduped},
    )


@bp.route("/demo/send", methods=["POST"])
def demo_send():
    """Runs a canned alert through the exact same pipeline a real EDR webhook call would
    use — in-process, not a real HTTP round trip, so the demo button works identically
    under `flask run` and behind a load balancer with no self-referential network call.
    """
    payload = next_payload(_demo_counter["n"])
    _demo_counter["n"] += 1
    process_alert(payload)
    return redirect(url_for("views.index"))
