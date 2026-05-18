"""DOJAA application package."""

from __future__ import annotations

import logging

from flask import Flask

from .settings import Settings, load_settings

# Load .env from the project root if python-dotenv is installed. Silent no-op
# if the package isn't present or the file doesn't exist.
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover — optional dep
    pass


def create_app(settings: Settings | None = None) -> Flask:
    """Build and configure the Flask app."""
    settings = settings or load_settings()

    logging.basicConfig(
        level=logging.DEBUG if settings.debug else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    app.config["SECRET_KEY"] = settings.secret_key
    app.config["DOJAA_SETTINGS"] = settings

    from .blueprints import register_blueprints

    register_blueprints(app)
    return app
