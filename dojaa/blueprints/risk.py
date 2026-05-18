"""Risk — aggregate risk analytics.

Tier distribution, top-N risky assets (linked to host detail), per-source
split, and a frequency table of which risk drivers fired most. The detail
view of any single asset lives on the Hosts tab.
"""

from __future__ import annotations

from collections import Counter

from flask import Blueprint, render_template

from ..risk_tiers import risk_bucket, risk_tier_counts
from ..services.exports import csv_response
from ._support import current_user, format_freshness, get_dashboard_data, require_login

bp = Blueprint("risk", __name__)


def _score(a: dict) -> float:
    try:
        return float(a.get("risk_score") or 0)
    except (TypeError, ValueError):
        return 0.0


def _tier_split(rows: list[dict]) -> dict[str, int]:
    out = {"low": 0, "medium": 0, "high": 0, "unknown": 0}
    for r in rows:
        out[risk_bucket(r.get("risk_score"))] += 1
    return out


@bp.route("/risk")
@require_login
def index():
    data = get_dashboard_data()
    shodan = data.get("shodan") or []
    censys = data.get("censys") or []
    combined = shodan + censys

    risk_low, risk_mid, risk_high = risk_tier_counts(shodan, censys)
    top_assets = sorted(combined, key=_score, reverse=True)[:25]

    driver_counter: Counter[str] = Counter()
    for asset in combined:
        for issue in asset.get("issues") or []:
            driver_counter[issue] += 1

    return render_template(
        "risk/index.html",
        user=current_user(),
        freshness=format_freshness(data.get("_cache_freshness")),
        risk_low=risk_low,
        risk_mid=risk_mid,
        risk_high=risk_high,
        total=risk_low + risk_mid + risk_high,
        top_assets=top_assets,
        driver_rows=driver_counter.most_common(15),
        tier_counts_by_source={
            "shodan": _tier_split(shodan),
            "censys": _tier_split(censys),
        },
    )


@bp.route("/risk.csv")
@require_login
def export_csv():
    data = get_dashboard_data()
    combined = (data.get("shodan") or []) + (data.get("censys") or [])
    rows = sorted(combined, key=_score, reverse=True)
    header = ("ip", "source", "service", "port", "risk_score", "severity", "issues")
    return csv_response(
        "dojaa_risk.csv",
        header,
        (
            (
                r.get("ip", ""),
                r.get("source", ""),
                r.get("banner_service") or r.get("service") or "",
                r.get("port") or "",
                r.get("risk_score", 0),
                r.get("severity", ""),
                "; ".join(r.get("issues") or []),
            )
            for r in rows
        ),
    )
