"""SSL/TLS certificate intelligence."""

from __future__ import annotations

from flask import Blueprint, render_template

from ._support import current_user, get_dashboard_data, require_login

bp = Blueprint("ssl_tls", __name__)


@bp.route("/ssl-tls")
@require_login
def index():
    data = get_dashboard_data()
    return render_template(
        "ssl_tls/index.html",
        user=current_user(),
        ssl_tls=data.get("ssl_tls", []),
    )
