"""Risk — aggregate risk analytics.

Tier distribution, top-N risky assets (linked back to the host detail page —
not duplicated inline), and a breakdown of which risk drivers fired most.
"""

from __future__ import annotations

from collections import Counter

from flask import Blueprint, render_template

from ..risk_tiers import risk_bucket, risk_tier_counts
from ._support import current_user, get_dashboard_data, require_login

bp = Blueprint("risk", __name__)


@bp.route("/risk")
@require_login
def index():
    data = get_dashboard_data()
    shodan = data.get("shodan") or []
    censys = data.get("censys") or []
    risk_low, risk_mid, risk_high = risk_tier_counts(shodan, censys)
    combined = shodan + censys

    # Top-N risky assets — sorted desc, linked to host detail.
    def _score(a: dict) -> float:
        try:
            return float(a.get("risk_score") or 0)
        except (TypeError, ValueError):
            return 0.0

    top_assets = sorted(combined, key=_score, reverse=True)[:10]

    # Driver frequency — which "issues" fired across the surface.
    driver_counter: Counter[str] = Counter()
    for asset in combined:
        for issue in asset.get("issues") or []:
            driver_counter[issue] += 1

    tier_counts_by_source = {
        "shodan": _tier_split(shodan),
        "censys": _tier_split(censys),
    }

    return render_template(
        "risk/index.html",
        user=current_user(),
        risk_low=risk_low,
        risk_mid=risk_mid,
        risk_high=risk_high,
        total=risk_low + risk_mid + risk_high,
        top_assets=top_assets,
        driver_rows=driver_counter.most_common(10),
        tier_counts_by_source=tier_counts_by_source,
    )


def _tier_split(rows: list[dict]) -> dict[str, int]:
    out = {"low": 0, "medium": 0, "high": 0, "unknown": 0}
    for r in rows:
        out[risk_bucket(r.get("risk_score"))] += 1
    return out
