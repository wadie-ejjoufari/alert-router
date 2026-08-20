"""Tiny sqlite3 wrapper. No ORM — the schema is small enough that raw SQL is clearer."""
from __future__ import annotations

import os
import sqlite3

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    received_at TEXT NOT NULL,
    source TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    asset_criticality TEXT NOT NULL,
    indicator_type TEXT,
    indicator_value TEXT,
    message TEXT,
    raw_payload TEXT NOT NULL,
    dedup_hash TEXT NOT NULL,
    dedup_of TEXT,
    enrichment_json TEXT,
    routing_decision TEXT,
    routing_detail TEXT,
    status TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_dedup_hash ON alerts (dedup_hash);
CREATE INDEX IF NOT EXISTS idx_alerts_received_at ON alerts (received_at);
"""


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        path = current_app.config["DATABASE_PATH"]
        os.makedirs(os.path.dirname(path), exist_ok=True)
        conn = sqlite3.connect(path, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


def close_db(_exc=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app) -> None:
    with app.app_context():
        conn = get_db()
        conn.executescript(SCHEMA)
        conn.commit()


def init_app(app) -> None:
    app.teardown_appcontext(close_db)
    init_db(app)
