"""Minimal in-memory per-IP sliding-window rate limiter.

State lives on the Flask app instance (one process, one dict) — enough to blunt casual
scripted abuse of the public demo endpoints. Not a substitute for a real rate limiter
(Redis, an API gateway) under real traffic; consistent with the rest of this project's
demo scope (see README: "not built for high alert volume").
"""
from __future__ import annotations

import time
from collections import defaultdict
from functools import wraps

from flask import current_app, jsonify, request


def init_app(app) -> None:
    app.extensions["rate_limit_hits"] = defaultdict(list)


def _client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def rate_limit(max_requests: int, window_seconds: int):
    """Caps a view to `max_requests` per `window_seconds`, per client IP per endpoint."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            hits_by_key = current_app.extensions["rate_limit_hits"]
            key = f"{request.endpoint}:{_client_ip()}"
            now = time.monotonic()
            cutoff = now - window_seconds
            hits = [t for t in hits_by_key[key] if t >= cutoff]
            if len(hits) >= max_requests:
                return jsonify({"error": "rate limit exceeded, try again shortly"}), 429
            hits.append(now)
            hits_by_key[key] = hits
            return view(*args, **kwargs)
        return wrapped
    return decorator
