"""Alert Router ("SOAR-lite") application factory."""
from __future__ import annotations

import os

from flask import Flask

from . import db as db_module
from . import ratelimit


def create_app(config_overrides: dict | None = None) -> Flask:
    app = Flask(__name__)

    app.config.update(
        DATABASE_PATH=os.environ.get("DATABASE_PATH", os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "alerts.db"
        )),
        WEBHOOK_SHARED_SECRET=os.environ.get("WEBHOOK_SHARED_SECRET", "changeme-dev-secret"),
        DEDUP_WINDOW_MINUTES=int(os.environ.get("DEDUP_WINDOW_MINUTES", "15")),
        ABUSEIPDB_API_KEY=os.environ.get("ABUSEIPDB_API_KEY", ""),
        SLACK_WEBHOOK_URL=os.environ.get("SLACK_WEBHOOK_URL", ""),
        JIRA_BASE_URL=os.environ.get("JIRA_BASE_URL", ""),
        JIRA_EMAIL=os.environ.get("JIRA_EMAIL", ""),
        JIRA_API_TOKEN=os.environ.get("JIRA_API_TOKEN", ""),
        JIRA_PROJECT_KEY=os.environ.get("JIRA_PROJECT_KEY", ""),
        RECENT_ALERTS_LIMIT=int(os.environ.get("RECENT_ALERTS_LIMIT", "50")),
    )
    if config_overrides:
        app.config.update(config_overrides)

    db_module.init_app(app)
    ratelimit.init_app(app)

    from .webhook import bp as webhook_bp
    from .views import bp as views_bp

    app.register_blueprint(webhook_bp)
    app.register_blueprint(views_bp)

    return app
