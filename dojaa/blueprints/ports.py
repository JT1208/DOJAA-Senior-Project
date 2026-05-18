"""Ports — port-distribution analytics.

Answers "which ports/services are exposed across the attack surface?". Does
**not** rehash per-host rows (that's the Hosts tab's job).
"""

from __future__ import annotations

from collections import Counter

from flask import Blueprint, render_template

from ._support import current_user, get_dashboard_data, require_login

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


@bp.route("/ports")
@require_login
def index():
    data = get_dashboard_data()
    hosts = (data.get("shodan") or []) + (data.get("censys") or [])

    port_counter: Counter[int] = Counter()
    risky_port_counter: Counter[int] = Counter()
    service_counter: Counter[str] = Counter()
    for h in hosts:
        port = _port_to_int(h.get("port"))
        if port is None:
            continue
        port_counter[port] += 1
        try:
            score = float(h.get("risk_score") or 0)
        except (TypeError, ValueError):
            score = 0
        if score >= 50:
            risky_port_counter[port] += 1
        svc = (h.get("service") or _PORT_SERVICE_HINT.get(port) or "Unknown").strip()
        service_counter[svc] += 1

    port_rows = [
        {
            "port": port,
            "service_hint": _PORT_SERVICE_HINT.get(port, "—"),
            "count": count,
            "risky_count": risky_port_counter.get(port, 0),
        }
        for port, count in port_counter.most_common()
    ]
    service_rows = [
        {"service": svc, "count": count}
        for svc, count in service_counter.most_common(15)
    ]
    return render_template(
        "ports/index.html",
        user=current_user(),
        port_rows=port_rows,
        service_rows=service_rows,
        total_exposed=sum(port_counter.values()),
        unique_ports=len(port_counter),
    )
