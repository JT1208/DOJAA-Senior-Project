"""PDF report download."""

from __future__ import annotations

from datetime import datetime
from io import BytesIO

from flask import Blueprint, flash, redirect, send_file, url_for

from ..report_pdf import build_dashboard_report_pdf
from ._support import current_user, get_dashboard_data, require_login

bp = Blueprint("reports", __name__)


@bp.route("/reports/dashboard.pdf")
@require_login
def dashboard_pdf():
    data = get_dashboard_data(rescan=False)
    pdf_bytes, err = build_dashboard_report_pdf(
        data.get("shodan", []),
        data.get("censys", []),
        data.get("cves", []),
        data.get("ssl_tls") or [],
        current_user(),
    )
    if err:
        flash(err, "danger")
        return redirect(url_for("dashboard.index"))

    fname = f"DOJAA_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    return send_file(
        BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=fname,
    )
