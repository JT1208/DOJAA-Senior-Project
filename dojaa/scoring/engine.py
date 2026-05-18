"""Per-host risk evaluator.

For every discovered host we:

1. Build a :class:`HostSnapshot` summarising its full external surface
   (ports, banners, certs, matched CVEs, inventory state).
2. Evaluate the official :mod:`findings` catalog against the snapshot
   — each matching finding contributes its CVSS v3.1 base score, CWE,
   NIST 800-53 controls, MITRE ATT&CK techniques and references.
3. Aggregate the findings into a single 0–100 risk score:

   - **headline** = max(CVSS) across findings — the worst single issue
   - **weighted_score** = the headline plus a log-scaled bonus for
     additional findings (so a host with five Highs scores higher than
     a host with one)
   - any matched CVE in the CISA KEV catalog promotes the host to
     "Critical" regardless of CVSS aggregation (BOD 22-01)

4. Map the 0–100 score back to CVSS severity bands per spec
   (None / Low / Medium / High / Critical).

The result is a list of dicts attached to each asset row under the
``findings`` key, plus the headline ``risk_score`` / ``severity`` /
``cvss_headline`` summary the UI renders.
"""

from __future__ import annotations

import math
from collections.abc import Iterable

from .cvss import severity_from_score
from .findings import HostSnapshot, evaluate_findings


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def _aggregate(findings: list[dict], has_kev: bool) -> tuple[float, float, str]:
    """Return (cvss_headline, score_0_100, severity).

    ``cvss_headline`` is the worst single CVSS base score; the
    ``score_0_100`` adds a logarithmic bonus for each additional
    finding so volume of issues moves the needle without overwhelming
    severity.
    """
    if not findings:
        return 0.0, 0.0, "None"

    scores = [f["cvss"]["score"] for f in findings if f.get("cvss")]
    if not scores:
        return 0.0, 0.0, "None"

    headline = max(scores)
    # Volume bonus: +log10(n) * 4, capped at +1.5 CVSS-equivalent.
    n = len(scores)
    volume_bonus = min(math.log10(n) * 4.0, 1.5) if n > 1 else 0.0
    aggregate_cvss = min(10.0, headline + volume_bonus)

    # CISA KEV override: any actively-exploited CVE on the host bumps
    # the aggregate to at least 9.0 (Critical) — BOD 22-01.
    if has_kev:
        aggregate_cvss = max(aggregate_cvss, 9.0)

    score_100 = round(aggregate_cvss * 10.0, 1)
    severity = severity_from_score(aggregate_cvss)
    return round(aggregate_cvss, 1), score_100, severity


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_snapshots(rows: Iterable[dict],
                    cves_by_ip: dict[str, list[dict]] | None = None,
                    certs_by_ip: dict[str, list[dict]] | None = None,
                    ) -> dict[str, HostSnapshot]:
    """Group asset rows into one :class:`HostSnapshot` per IP."""
    grouped: dict[str, dict] = {}
    for r in rows:
        ip = r.get("ip")
        if not ip:
            continue
        bucket = grouped.setdefault(ip, {
            "ports": set(),
            "services": [],
            "banners": [],
            "known": r.get("known"),
        })
        if r.get("port") is not None:
            try:
                bucket["ports"].add(int(r["port"]))
            except (TypeError, ValueError):
                pass
        bucket["services"].append(r)
        if r.get("banner"):
            bucket["banners"].append(r["banner"])
        # Latest non-None known value wins (the inventory check fills it
        # the same way for every row of the same IP).
        if bucket["known"] is None and r.get("known") is not None:
            bucket["known"] = r["known"]

    cves_by_ip = cves_by_ip or {}
    certs_by_ip = certs_by_ip or {}

    snapshots: dict[str, HostSnapshot] = {}
    for ip, b in grouped.items():
        snapshots[ip] = HostSnapshot(
            ip=ip,
            ports=frozenset(b["ports"]),
            services=tuple(b["services"]),
            banners=tuple(b["banners"]),
            known=b["known"],
            matched_cves=tuple(cves_by_ip.get(ip, [])),
            tls_certs=tuple(certs_by_ip.get(ip, [])),
        )
    return snapshots


def score_snapshot(snapshot: HostSnapshot) -> dict:
    """Evaluate findings + aggregate into the per-host risk summary."""
    findings = evaluate_findings(snapshot)
    has_kev = any(c.get("is_kev") for c in snapshot.matched_cves)

    cvss_headline, score_100, severity = _aggregate(findings, has_kev=has_kev)

    # Surface every contributing CVE so the UI can list them under the
    # host detail page without re-correlating.
    cves = [
        {
            "cve_id": c.get("cve_id"),
            "severity": c.get("severity"),
            "cvss_score": c.get("cvss_score"),
            "cvss_vector": c.get("cvss_vector"),
            "is_kev": bool(c.get("is_kev")),
            "kev_due_date": c.get("kev_due_date"),
            "epss_score": c.get("epss_score"),
            "epss_percentile": c.get("epss_percentile"),
            "service": c.get("service"),
        }
        for c in snapshot.matched_cves
    ]

    return {
        "ip": snapshot.ip,
        "findings": findings,
        "cves": cves,
        "cvss_headline": cvss_headline,
        "risk_score": score_100,
        "severity": severity,
        "kev_present": has_kev,
    }


def attach_per_row(rows: list[dict],
                   snapshots: dict[str, HostSnapshot],
                   summaries: dict[str, dict]) -> list[dict]:
    """Stamp each asset row with the host-level risk summary.

    The rows themselves remain row-shaped (one per ip+port) because
    the tables in the UI are indexed that way, but every row carries
    the same per-host risk data so detail pages don't have to re-query.
    """
    for r in rows:
        ip = r.get("ip")
        summary = summaries.get(ip)
        if not summary:
            r.setdefault("findings", [])
            r.setdefault("risk_score", 0.0)
            r.setdefault("severity", "None")
            r.setdefault("cvss_headline", 0.0)
            r.setdefault("kev_present", False)
            r.setdefault("issues", [])
            r.setdefault("recommendations", [])
            continue
        r["findings"] = summary["findings"]
        r["risk_score"] = summary["risk_score"]
        r["severity"] = summary["severity"]
        r["cvss_headline"] = summary["cvss_headline"]
        r["kev_present"] = summary["kev_present"]
        # Legacy fields the existing UI / tables read.
        r["issues"] = [f["title"] for f in summary["findings"]]
        r["recommendations"] = list(dict.fromkeys(
            f["remediation"] for f in summary["findings"]
        ))
        r["matched_cves"] = summary["cves"]
    return rows
