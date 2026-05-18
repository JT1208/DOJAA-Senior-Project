"""Compatibility shim — risk scoring now lives in :mod:`dojaa.scoring`.

The original module computed an ad-hoc 0–100 score from a handful of
hard-coded point values. It has been replaced by the formal,
standards-based pipeline in :mod:`dojaa.scoring.engine`, which scores
each host against the catalog in :mod:`dojaa.scoring.findings` using
CVSS v3.1, CWE, NIST 800-53, MITRE ATT&CK and CISA-KEV / EPSS.

The two functions exported here are kept only to satisfy callers that
still import them (tests, scripts). All they do is delegate.
"""

from __future__ import annotations

from collections.abc import Iterable

from .scoring.engine import build_snapshots, score_snapshot
from .scoring.findings import HostSnapshot


def build_host_context(rows: Iterable[dict]) -> dict[str, HostSnapshot]:
    """Legacy alias for :func:`dojaa.scoring.engine.build_snapshots`."""
    return build_snapshots(rows)


def calculate_risk(asset: dict, host_context=None) -> dict:
    """Compatibility wrapper around the snapshot-based scorer.

    Builds a single-row snapshot if no ``host_context`` is supplied,
    scores it, and merges the resulting fields back onto ``asset`` —
    matching the original mutating contract.
    """
    if host_context and isinstance(host_context, HostSnapshot):
        snap = host_context
    else:
        snap = HostSnapshot(
            ip=asset.get("ip") or "unknown",
            ports=frozenset(
                {int(asset["port"])} if asset.get("port") is not None else set()
            ),
            services=(asset,),
            banners=(asset.get("banner") or "",),
            known=asset.get("known"),
        )
    summary = score_snapshot(snap)
    asset["findings"] = summary["findings"]
    asset["risk_score"] = summary["risk_score"]
    asset["severity"] = summary["severity"]
    asset["cvss_headline"] = summary["cvss_headline"]
    asset["kev_present"] = summary["kev_present"]
    asset["issues"] = [f["title"] for f in summary["findings"]]
    asset["recommendations"] = list(dict.fromkeys(
        f["remediation"] for f in summary["findings"]
    ))
    return asset
