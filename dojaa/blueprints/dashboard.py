"""Executive overview — KPIs, actionable widgets, deep links.

The dashboard intentionally contains no detail tables — those belong on
their respective tabs. What it owns: signals that tell you *where to look
first*. Each KPI tile links into a scoped detail view, and each side widget
is a 5-item teaser with a "see all" link.
"""

from __future__ import annotations

from flask import Blueprint, render_template

from ..risk_tiers import risk_tier_counts
from ._support import current_user, format_freshness, get_dashboard_data, require_login

bp = Blueprint("dashboard", __name__)


def _safe_int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _safe_float(v) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _critical_or_high(cves: list[dict]) -> int:
    return sum(
        1 for c in cves or [] if (c.get("severity") or "").upper() in ("CRITICAL", "HIGH")
    )


def _expiring_within(ssl_tls: list[dict], days: int) -> list[dict]:
    out = []
    for c in ssl_tls or []:
        d = _safe_int(c.get("days_left"))
        if d is not None and d <= days:
            out.append(c)
    return out


def _top_risky_hosts(shodan: list[dict], censys: list[dict], n: int) -> list[dict]:
    rows = sorted(shodan + censys, key=lambda a: _safe_float(a.get("risk_score")), reverse=True)
    return rows[:n]


def _top_cves(cves: list[dict], n: int) -> list[dict]:
    # Order by CVSS score desc; missing scores sink to the bottom.
    def key(c):
        s = c.get("cvss_score")
        try:
            return -float(s)
        except (TypeError, ValueError):
            return 0.0

    return sorted(cves or [], key=key)[:n]


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
    expiring_30 = _expiring_within(ssl_tls, 30)

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
        cves_critical=_critical_or_high(cves),
        cert_count=len(ssl_tls),
        certs_expiring_30d=len(expiring_30),
        ssh_exposed=sum(1 for a in shodan + censys if a.get("ssh_exposed")),
        http_exposed=sum(1 for a in shodan + censys if a.get("http_exposed")),
        https_exposed=sum(1 for a in shodan + censys if a.get("https_exposed")),
        freshness=format_freshness(data.get("_cache_freshness")),
        top_risky=_top_risky_hosts(shodan, censys, 5),
        expiring_soon=sorted(expiring_30, key=lambda c: _safe_int(c.get("days_left")) or 9999)[:5],
        latest_cves=_top_cves(cves, 5),
    )
