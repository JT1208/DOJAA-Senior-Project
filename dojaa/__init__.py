"""DOJAA application package."""

from __future__ import annotations

import logging

from flask import Flask

from .settings import Settings, load_settings

# Load .env at import time. Walks up from CWD so it works even when flask is
# invoked from a subdirectory. Prints a one-line diagnostic so missing
# credentials are obvious from the terminal rather than silently skipped.
import sys as _sys


def _bootstrap_dotenv() -> None:
    try:
        from dotenv import find_dotenv, load_dotenv
    except ImportError:
        print(
            "[dojaa] WARNING: python-dotenv is not installed; .env files will "
            "NOT be auto-loaded. Run `poetry install` or `pip install python-dotenv`.",
            file=_sys.stderr,
        )
        return

    path = find_dotenv(usecwd=True)
    if not path:
        print(
            "[dojaa] WARNING: no .env file found in CWD or any parent. "
            "API keys must already be exported in your shell.",
            file=_sys.stderr,
        )
        return

    load_dotenv(path, override=False)
    print(f"[dojaa] loaded environment from {path}", file=_sys.stderr)


_bootstrap_dotenv()


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
