"""Hosts — the sole place host-related functionality lives.

Owns the combined Shodan + Censys inventory plus all host actions: search,
source/risk/port filtering, CSV export, rescan, and the per-asset
drilldown page.

No other blueprint renders host tables or per-host actions.
"""

from __future__ import annotations

from collections import Counter

from flask import Blueprint, abort, render_template, request

from ..services.exports import csv_response
from ._support import current_user, format_freshness, get_dashboard_data, require_login

bp = Blueprint("hosts", __name__)


def _all_hosts(data: dict) -> list[dict]:
    return (data.get("shodan") or []) + (data.get("censys") or [])


def _related_cves(asset: dict, cves: list[dict]) -> list[dict]:
    needles = {
        (asset.get("service") or "").strip().lower(),
        (asset.get("banner_product") or "").strip().lower(),
        (asset.get("banner_service") or "").strip().lower(),
    }
    needles.discard("")
    needles.discard("unknown")
    if not needles:
        return []
    out: list[dict] = []
    for cve in cves or []:
        s = (cve.get("service") or "").strip().lower()
        if not s:
            continue
        if any(n in s or s in n for n in needles):
            out.append(cve)

    def key(c: dict) -> float:
        v = c.get("cvss_score")
        try:
            return -float(v)
        except (TypeError, ValueError):
            return 0.0

    out.sort(key=key)
    return out[:8]


def _related_cert(asset: dict, ssl_tls: list[dict]) -> dict | None:
    ip = asset.get("ip")
    if not ip:
        return None
    for cert in ssl_tls or []:
        if cert.get("ip") == ip:
            return cert
    return None


@bp.route("/hosts")
@require_login
def index():
    data = get_dashboard_data()
    hosts = _all_hosts(data)
    sources = Counter(h.get("source", "unknown") for h in hosts)
    return render_template(
        "hosts/index.html",
        user=current_user(),
        hosts=hosts,
        host_count=len({h.get("ip") for h in hosts if h.get("ip")}),
        source_counts=sources,
        freshness=format_freshness(data.get("_cache_freshness")),
        preset_risk=(request.args.get("risk") or "").strip().lower() or None,
        preset_source=(request.args.get("source") or "").strip().lower() or None,
        preset_port=(request.args.get("port") or "").strip() or None,
    )


@bp.route("/hosts/<ip>")
@require_login
def detail(ip: str):
    data = get_dashboard_data()
    hosts = _all_hosts(data)
    asset = next((a for a in hosts if a.get("ip") == ip), None)
    if not asset:
        abort(404)
    return render_template(
        "hosts/detail.html",
        user=current_user(),
        asset=asset,
        related_cves=_related_cves(asset, data.get("cves", [])),
        related_cert=_related_cert(asset, data.get("ssl_tls", [])),
    )


@bp.route("/hosts.csv")
@require_login
def export_csv():
    data = get_dashboard_data()
    hosts = _all_hosts(data)
    header = (
        "ip", "source", "port", "service", "service_intel", "banner_summary",
        "risk_score", "severity", "shadow_asset", "provider",
    )
    rows = (
        (
            h.get("ip", ""),
            h.get("source", ""),
            h.get("port", ""),
            h.get("service", ""),
            h.get("service_intel", ""),
            h.get("banner_summary", ""),
            h.get("risk_score", ""),
            h.get("severity", ""),
            "yes" if h.get("shadow_asset") else "no",
            h.get("provider", ""),
        )
        for h in hosts
    )
    return csv_response("dojaa_hosts.csv", header, rows)
