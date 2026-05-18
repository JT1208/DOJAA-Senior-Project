"""Executive overview — KPIs and pointers into the detail tabs.

The dashboard intentionally contains **no** per-asset, per-port, per-CVE, or
per-cert tables. Those belong to the dedicated tabs. This page exists to
answer "what should I look at first?" at a glance.
"""

from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, render_template

from ..risk_tiers import risk_tier_counts
from ._support import current_user, get_dashboard_data, require_login

bp = Blueprint("dashboard", __name__)


def _expiring_cert_count(ssl_tls: list[dict], within_days: int = 30) -> int:
    n = 0
    for c in ssl_tls or []:
        days = c.get("days_left")
        try:
            if days is not None and int(days) <= within_days:
                n += 1
        except (TypeError, ValueError):
            continue
    return n


def _critical_cve_count(cves: list[dict]) -> int:
    n = 0
    for c in cves or []:
        sev = (c.get("severity") or "").upper()
        if sev in ("CRITICAL", "HIGH"):
            n += 1
    return n


def _format_freshness(iso: str | None) -> str | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return None
    delta = datetime.now(timezone.utc) - dt
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60} min ago"
    if seconds < 86400:
        return f"{seconds // 3600} h ago"
    return dt.strftime("%Y-%m-%d %H:%M UTC")


@bp.route("/dashboard")
@require_login
def index():
    data = get_dashboard_data()
    shodan = data.get("shodan", [])
    censys = data.get("censys", [])
    cves = data.get("cves", [])
    ssl_tls = data.get("ssl_tls", [])

    risk_low, risk_mid, risk_high = risk_tier_counts(shodan, censys)
    unique_hosts = len({a.get("ip") for a in shodan + censys if a.get("ip")})

    return render_template(
        "dashboard.html",
        user=current_user(),
        host_count=unique_hosts,
        shodan_count=len(shodan),
        censys_count=len(censys),
        risk_low=risk_low,
        risk_mid=risk_mid,
        risk_high=risk_high,
        cves_total=len(cves),
        cves_critical=_critical_cve_count(cves),
        cert_count=len(ssl_tls),
        certs_expiring_30d=_expiring_cert_count(ssl_tls, within_days=30),
        ssh_exposed=sum(1 for a in shodan + censys if a.get("ssh_exposed")),
        http_exposed=sum(1 for a in shodan + censys if a.get("http_exposed")),
        https_exposed=sum(1 for a in shodan + censys if a.get("https_exposed")),
        freshness=_format_freshness(data.get("_cache_freshness")),
    )
