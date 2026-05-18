"""CVE findings."""

from __future__ import annotations

from flask import Blueprint, render_template

from ._support import current_user, get_dashboard_data, require_login

bp = Blueprint("cves", __name__)


@bp.route("/cves")
@require_login
def index():
    data = get_dashboard_data()
    return render_template(
        "cves/index.html",
        user=current_user(),
        cves=data.get("cves", []),
    )
