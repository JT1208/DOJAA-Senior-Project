"""DOJAA application package."""

from __future__ import annotations

import logging
from datetime import timedelta

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


def _apply_security_config(app: Flask, settings: Settings) -> None:
    """Lock down session cookies + session lifetime.

    SESSION_COOKIE_SECURE is set unconditionally — when running over plain
    HTTP locally, browsers will refuse the cookie and you'll see logout
    behaviour, which is the correct fail-closed default. Override with
    FLASK_DEBUG=true for local HTTP development.
    """
    app.config.update(
        SESSION_COOKIE_SECURE=not settings.debug,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_REFRESH_EACH_REQUEST=True,
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        # Hide the framework version from error pages / 404s.
        PROPAGATE_EXCEPTIONS=settings.debug,
    )


def _register_security_headers(app: Flask) -> None:
    """Add defence-in-depth response headers on every request."""

    csp = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "base-uri 'self'; "
        "object-src 'none'"
    )

    @app.after_request
    def _set_headers(response):
        response.headers.setdefault("Content-Security-Policy", csp)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=(), payment=()",
        )
        # Browsers ignore HSTS over plain HTTP, so it's safe to always send.
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )
        response.headers.pop("Server", None)
        return response


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

    _apply_security_config(app, settings)
    _register_security_headers(app)

    if settings.auth_disabled:
        logging.getLogger(__name__).warning(
            "DOJAA_AUTH_DISABLED is true — the dashboard is reachable without "
            "login. Unset this before any non-local deployment."
        )

    from .blueprints import register_blueprints

    register_blueprints(app)
    return app
