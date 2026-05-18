"""Cross-blueprint helpers: auth decorator and shared pipeline-data accessor."""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable

from flask import current_app, flash, redirect, request, session, url_for

from ..pipeline import run_pipeline


def require_login(func: Callable) -> Callable:
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any):
        settings = current_app.config["DOJAA_SETTINGS"]
        if settings.auth_disabled:
            return func(*args, **kwargs)
        if "user" not in session:
            return redirect(url_for("auth.login"))
        return func(*args, **kwargs)

    return wrapper


def current_user() -> str | None:
    settings = current_app.config["DOJAA_SETTINGS"]
    if settings.auth_disabled:
        return "demo"
    return session.get("user")


def get_dashboard_data(rescan: bool | None = None) -> dict:
    """Run (or read) the pipeline and flash any notices.

    Pass ``rescan=True`` for an explicit refresh; otherwise the ``rescan``
    query-string flag is honoured.
    """
    if rescan is None:
        rescan = request.args.get("rescan", "false").lower() == "true"
    data = run_pipeline(use_api=rescan)
    for msg in data.get("_pipeline_notices") or []:
        flash(msg, "warning")
    return data
