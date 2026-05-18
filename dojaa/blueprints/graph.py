"""Attack-surface graph view."""

from __future__ import annotations

from flask import Blueprint, render_template

from ._support import current_user, get_dashboard_data, require_login

bp = Blueprint("graph", __name__)


@bp.route("/graph")
@require_login
def index():
    data = get_dashboard_data()
    hosts = (data.get("shodan") or []) + (data.get("censys") or [])
    return render_template(
        "graph/index.html",
        user=current_user(),
        hosts=hosts,
    )
