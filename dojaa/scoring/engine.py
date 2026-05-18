"""Per-host risk evaluator.

Scoring rules (industry-standard, defensible):

1.  Build a :class:`HostSnapshot` summarising the host's external
    surface (ports, banners, certs, matched CVEs, inventory state).
2.  Evaluate the formal :mod:`findings` catalog against the snapshot —
    each matching finding carries its CVSS v3.1 base score, CWE,
    NIST 800-53 controls, MITRE ATT&CK techniques and references.
3.  For the special "CVE match" finding (category ``cve``) the static
    catalog vector is **overridden** with the worst NVD CVSS among the
    actually-matched CVEs. This way a host with only historical
    low-impact CVEs no longer reports as High.
4.  Compute the host's **headline CVSS** as the *maximum* CVSS among
    findings whose category is ``vulnerability`` or ``cve``. Findings
    in the ``exposure`` and ``hardening`` categories are listed in the
    UI but do NOT inflate the headline — they are posture / hygiene
    observations, not exploitable weaknesses.
5.  If any matched CVE is in CISA KEV, the headline is raised to at
    least 9.0 (Critical) per BOD 22-01.
6.  The 0–100 ``risk_score`` is the headline × 10 (rounded). It is no
    longer inflated by a "volume bonus" — adding two unrelated Mediums
    should not yield a High under CVSS semantics.

The result attaches the full finding list, the CVE match list, and
the headline summary to every asset row.
"""

from __future__ import annotations

from collections.abc import Iterable

from .cvss import severity_from_score
from .findings import HostSnapshot, evaluate_findings


# Categories that count toward the headline CVSS.
_HEADLINE_CATEGORIES = {"vulnerability", "cve"}


def _coerce_cvss(value) -> float | None:
    """Coerce NVD's CVSS field (which can be float, str, '-') to float | None."""
    if value in (None, "", "-"):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _patch_cve_finding(finding: dict, matched_cves: tuple[dict, ...]) -> None:
    """For the 'cve' category finding, override its CVSS with the worst
    actually-matched CVE's NVD score (when available)."""
    scores = [_coerce_cvss(c.get("cvss_score")) for c in matched_cves]
    scores = [s for s in scores if s is not None]
    if not scores:
        return
    worst = max(scores)
    worst_cve = next(
        (c for c in matched_cves
         if _coerce_cvss(c.get("cvss_score")) == worst),
        None,
    )
    finding["cvss"] = {
        "vector": (worst_cve or {}).get("cvss_vector") or finding["cvss"]["vector"],
        "score": round(worst, 1),
        "severity": severity_from_score(worst),
    }
    finding["title"] = (
        f"CVE matches — worst: "
        f"{(worst_cve or {}).get('cve_id', 'unknown')} "
        f"(CVSS {worst:.1f})"
    )


def _aggregate(findings: list[dict], has_kev: bool) -> tuple[float, float, str]:
    """Return ``(cvss_headline, score_0_100, severity)``.

    The headline is the worst CVSS among findings whose category counts.
    KEV presence force-promotes to at least 9.0 (Critical) per CISA BOD
    22-01.
    """
    qualifying = [
        f for f in findings
        if f.get("category", "vulnerability") in _HEADLINE_CATEGORIES
    ]
    scores = [f["cvss"]["score"] for f in qualifying if f.get("cvss")]
    headline = max(scores) if scores else 0.0

    if has_kev:
        headline = max(headline, 9.0)

    return (
        round(headline, 1),
        round(headline * 10.0, 1),
        severity_from_score(headline),
    )


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
        if bucket["known"] is None and r.get("known") is not None:
            bucket["known"] = r["known"]

    cves_by_ip = cves_by_ip or {}
    certs_by_ip = certs_by_ip or {}

    return {
        ip: HostSnapshot(
            ip=ip,
            ports=frozenset(b["ports"]),
            services=tuple(b["services"]),
            banners=tuple(b["banners"]),
            known=b["known"],
            matched_cves=tuple(cves_by_ip.get(ip, [])),
            tls_certs=tuple(certs_by_ip.get(ip, [])),
        )
        for ip, b in grouped.items()
    }


def score_snapshot(snapshot: HostSnapshot) -> dict:
    """Evaluate findings + aggregate into the per-host risk summary."""
    findings = evaluate_findings(snapshot)
    has_kev = any(c.get("is_kev") for c in snapshot.matched_cves)

    # Patch the CVE-category finding with the actual worst-matched CVSS.
    for f in findings:
        if f.get("category") == "cve":
            _patch_cve_finding(f, snapshot.matched_cves)

    cvss_headline, score_100, severity = _aggregate(findings, has_kev=has_kev)

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

    # Group findings by category for cleaner UI rendering.
    by_cat: dict[str, list[dict]] = {"vulnerability": [], "cve": [],
                                      "exposure": [], "hardening": []}
    for f in findings:
        by_cat.setdefault(f.get("category", "vulnerability"), []).append(f)

    return {
        "ip": snapshot.ip,
        "findings": findings,
        "findings_by_category": by_cat,
        "cves": cves,
        "cvss_headline": cvss_headline,
        "risk_score": score_100,
        "severity": severity,
        "kev_present": has_kev,
    }


def attach_per_row(rows: list[dict],
                   snapshots: dict[str, HostSnapshot],
                   summaries: dict[str, dict]) -> list[dict]:
    """Stamp each asset row with the host-level risk summary."""
    for r in rows:
        ip = r.get("ip")
        summary = summaries.get(ip)
        if not summary:
            r.setdefault("findings", [])
            r.setdefault("findings_by_category", {})
            r.setdefault("risk_score", 0.0)
            r.setdefault("severity", "None")
            r.setdefault("cvss_headline", 0.0)
            r.setdefault("kev_present", False)
            r.setdefault("issues", [])
            r.setdefault("recommendations", [])
            continue
        r["findings"] = summary["findings"]
        r["findings_by_category"] = summary["findings_by_category"]
        r["risk_score"] = summary["risk_score"]
        r["severity"] = summary["severity"]
        r["cvss_headline"] = summary["cvss_headline"]
        r["kev_present"] = summary["kev_present"]
        r["issues"] = [f["title"] for f in summary["findings"]]
        r["recommendations"] = list(dict.fromkeys(
            f["remediation"] for f in summary["findings"]
        ))
        r["matched_cves"] = summary["cves"]
    return rows
