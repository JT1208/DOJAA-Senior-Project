"""CVE findings — list, filter, export, drill back to affected hosts."""

from __future__ import annotations

from collections import Counter

from flask import Blueprint, render_template

from ..services.exports import csv_response
from ._support import current_user, format_freshness, get_dashboard_data, require_login

bp = Blueprint("cves", __name__)


def _severity_counts(cves: list[dict]) -> dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for c in cves or []:
        s = (c.get("severity") or "UNKNOWN").upper()
        counts[s] = counts.get(s, 0) + 1
    return counts


def _affected_host_counts(cves: list[dict], hosts: list[dict]) -> dict[str, int]:
    """For each CVE service keyword, count hosts whose service / banner matches."""
    services = {(c.get("service") or "").strip().lower() for c in cves or [] if c.get("service")}
    services.discard("")
    out: dict[str, int] = {s: 0 for s in services}
    for h in hosts or []:
        haystack = " ".join(
            str(h.get(f) or "")
            for f in ("service", "banner_service", "banner_product")
        ).lower()
        if not haystack.strip():
            continue
        for s in services:
            if s and s in haystack:
                out[s] += 1
    return out


@bp.route("/cves")
@require_login
def index():
    data = get_dashboard_data()
    cves = data.get("cves", [])
    hosts = (data.get("shodan") or []) + (data.get("censys") or [])
    sev_counts = _severity_counts(cves)
    affected = _affected_host_counts(cves, hosts)

    services = sorted({(c.get("service") or "").strip() for c in cves if c.get("service")})

    # Enrich each row with the count of matching hosts (for the table column).
    for c in cves:
        c["_affected"] = affected.get((c.get("service") or "").strip().lower(), 0)

    return render_template(
        "cves/index.html",
        user=current_user(),
        freshness=format_freshness(data.get("_cache_freshness")),
        cves=cves,
        sev_counts=sev_counts,
        services=services,
        critical_high=sev_counts.get("CRITICAL", 0) + sev_counts.get("HIGH", 0),
    )


@bp.route("/cves.csv")
@require_login
def export_csv():
    data = get_dashboard_data()
    cves = data.get("cves", []) or []
    header = ("cve_id", "service", "severity", "cvss_score", "published", "cwe_ids", "description")
    return csv_response(
        "dojaa_cves.csv",
        header,
        (
            (
                c.get("cve_id", ""),
                c.get("service", ""),
                c.get("severity", ""),
                c.get("cvss_score", ""),
                c.get("published", ""),
                "; ".join(c.get("cwe_ids") or []),
                c.get("description", ""),
            )
            for c in cves
        ),
    )
