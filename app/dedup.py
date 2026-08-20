"""Deduplication: don't page a human five times for the same underlying event."""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

from .db import get_db


def compute_dedup_hash(source: str, alert_type: str, asset_id: str, indicator_value: Optional[str], message: str) -> str:
    key = "|".join([source, alert_type, asset_id, indicator_value or "", message or ""])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def find_recent_duplicate(dedup_hash: str, window_minutes: int) -> Optional[str]:
    """Return the id of a prior alert with the same hash inside the dedup window, if any."""
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()
    db = get_db()
    row = db.execute(
        """
        SELECT id FROM alerts
        WHERE dedup_hash = ? AND received_at >= ? AND dedup_of IS NULL
        ORDER BY received_at DESC
        LIMIT 1
        """,
        (dedup_hash, cutoff),
    ).fetchone()
    return row["id"] if row else None
