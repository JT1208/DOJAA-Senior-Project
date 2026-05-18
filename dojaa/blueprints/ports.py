"""Ports — port-distribution analytics with a hosts-on-port drilldown.

Answers "which ports/services are exposed across the surface?" and lets you
pivot into the Hosts tab pre-filtered to a chosen port. Per-host rows live
on the Hosts tab; this tab never duplicates them.
"""

from __future__ import annotations

from collections import Counter

from flask import Blueprint, abort, render_template

from ..services.exports import csv_response
from ._support import current_user, format_freshness, get_dashboard_data, require_login

bp = Blueprint("ports", __name__)


_PORT_SERVICE_HINT = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 465: "SMTPS", 587: "SMTP-Submission",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle DB",
    2049: "NFS", 3000: "Dev (Node/Grafana)", 3306: "MySQL", 3389: "RDP",
    5432: "Postgres", 5900: "VNC", 5984: "CouchDB", 6379: "Redis",
    8000: "HTTP-Alt", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB",
}


def _port_to_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _risk_score(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _compute(data: dict) -> dict:
    hosts = (data.get("shodan") or []) + (data.get("censys") or [])

    port_counter: Counter[int] = Counter()
    risky_port_counter: Counter[int] = Counter()
    service_counter: Counter[str] = Counter()
    sample_service_by_port: dict[int, str] = {}

    for h in hosts:
        port = _port_to_int(h.get("port"))
        if port is None:
            continue
        port_counter[port] += 1
        if _risk_score(h.get("risk_score")) >= 50:
            risky_port_counter[port] += 1
        svc = (h.get("service") or _PORT_SERVICE_HINT.get(port) or "Unknown").strip()
        service_counter[svc] += 1
        sample_service_by_port.setdefault(port, svc)

    port_rows = [
        {
            "port": port,
            "service_hint": _PORT_SERVICE_HINT.get(port, sample_service_by_port.get(port, "—")),
            "count": count,
            "risky_count": risky_port_counter.get(port, 0),
        }
        for port, count in port_counter.most_common()
    ]
    service_rows = [
        {"service": svc, "count": count}
        for svc, count in service_counter.most_common(15)
    ]
    return {
        "port_rows": port_rows,
        "service_rows": service_rows,
        "total_exposed": sum(port_counter.values()),
        "unique_ports": len(port_counter),
        "risky_ports": sum(1 for r in port_rows if r["risky_count"] > 0),
        "hosts": hosts,
    }


@bp.route("/ports")
@require_login
def index():
    data = get_dashboard_data()
    state = _compute(data)
    return render_template(
        "ports/index.html",
        user=current_user(),
        freshness=format_freshness(data.get("_cache_freshness")),
        port_rows=state["port_rows"],
        service_rows=state["service_rows"],
        total_exposed=state["total_exposed"],
        unique_ports=state["unique_ports"],
        risky_ports=state["risky_ports"],
    )


@bp.route("/ports/<int:port>")
@require_login
def detail(port: int):
    data = get_dashboard_data()
    hosts = (data.get("shodan") or []) + (data.get("censys") or [])
    matches = [h for h in hosts if _port_to_int(h.get("port")) == port]
    if not matches:
        abort(404)
    matches.sort(key=lambda h: _risk_score(h.get("risk_score")), reverse=True)
    return render_template(
        "ports/detail.html",
        user=current_user(),
        port=port,
        service_hint=_PORT_SERVICE_HINT.get(port, "—"),
        matches=matches,
        freshness=format_freshness(data.get("_cache_freshness")),
    )


@bp.route("/ports.csv")
@require_login
def export_csv():
    data = get_dashboard_data()
    state = _compute(data)
    header = ("port", "service_hint", "host_count", "risky_host_count")
    rows = (
        (r["port"], r["service_hint"], r["count"], r["risky_count"])
        for r in state["port_rows"]
    )
    return csv_response("dojaa_ports.csv", header, rows)
