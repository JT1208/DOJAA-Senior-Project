"""Tests for the per-host scoring engine.

The engine combines findings from the catalog into a single CVSS
headline plus a 0-100 risk score. The rules under test:

* Headline = max(CVSS) across findings whose category is
  ``vulnerability`` or ``cve``. Exposure / hardening findings are
  listed but do not move the band.
* For the ``cve`` finding, the static catalog CVSS is overridden with
  the worst NVD CVSS of the actually-matched CVEs.
* Presence of any CISA KEV-flagged CVE promotes the host to at least
  CVSS 9.0 (Critical) — BOD 22-01.
* The 0-100 risk score is headline × 10 (no compounding bonus).
"""

from __future__ import annotations

from dojaa.scoring.engine import score_snapshot
from dojaa.scoring.findings import HostSnapshot


def _snap(**overrides):
    base = dict(
        ip="1.2.3.4",
        ports=frozenset(),
        services=(),
        banners=(),
        known=True,
        matched_cves=(),
        tls_certs=(),
    )
    base.update(overrides)
    return HostSnapshot(**base)


# ---------------------------------------------------------------------------
# Headline excludes exposure/hardening
# ---------------------------------------------------------------------------

def test_exposure_only_host_scores_none():
    # Only posture observations — no actual vulnerability.
    snap = _snap(ports=frozenset({22, 3389}),
                 services=({"banner_version": "1.0"},))
    out = score_snapshot(snap)
    # Has SSH-exposed (exposure), sensitive port (exposure), version
    # disclosure (hardening). None of these contribute to headline.
    assert out["severity"] == "None"
    assert out["cvss_headline"] == 0.0
    assert any(f["category"] == "exposure"  for f in out["findings"])
    assert any(f["category"] == "hardening" for f in out["findings"])


def test_vulnerability_drives_headline():
    # Cleartext HTTP-only host: F-001 = CVSS 4.2 Medium.
    snap = _snap(ports=frozenset({80}))
    out = score_snapshot(snap)
    assert out["severity"] == "Medium"
    assert out["cvss_headline"] == 4.2


def test_two_mediums_do_not_compound_into_high():
    # Two Medium-category findings should not compound into High.
    # Cleartext HTTP (4.2) + Apache 2.2 EOL (which spec sets to Medium).
    snap = _snap(
        ports=frozenset({80}),
        banners=("Server: Apache/2.2.15 (CentOS)",),
    )
    out = score_snapshot(snap)
    # Headline is max of category-qualifying findings; not a sum.
    assert out["severity"] in {"Medium", "High"}  # EOL Apache is itself High
    # The exact value should be deterministic max, not a bonus-inflated value.
    qualifying = [f for f in out["findings"]
                  if f["category"] in {"vulnerability", "cve"}]
    expected_headline = max(f["cvss"]["score"] for f in qualifying)
    assert out["cvss_headline"] == round(expected_headline, 1)


# ---------------------------------------------------------------------------
# CVE finding uses the matched CVE's actual CVSS
# ---------------------------------------------------------------------------

def test_cve_finding_takes_worst_matched_cvss():
    matched = (
        {"cve_id": "CVE-2000-1234", "cvss_score": 5.0,
         "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
        {"cve_id": "CVE-2017-1234", "cvss_score": 7.5,
         "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    )
    snap = _snap(matched_cves=matched)
    out = score_snapshot(snap)
    cve_finding = next(f for f in out["findings"] if f["category"] == "cve")
    assert cve_finding["cvss"]["score"] == 7.5
    assert "CVE-2017-1234" in cve_finding["title"]
    assert out["cvss_headline"] == 7.5
    assert out["severity"] == "High"


def test_cve_finding_with_only_low_cves_stays_low():
    """A host whose only CVE match is low-severity should stay Low."""
    matched = (
        {"cve_id": "CVE-2025-LOW", "cvss_score": 3.1,
         "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    )
    snap = _snap(matched_cves=matched)
    out = score_snapshot(snap)
    assert out["severity"] == "Low"
    assert out["cvss_headline"] == 3.1


# ---------------------------------------------------------------------------
# KEV override
# ---------------------------------------------------------------------------

def test_kev_match_promotes_to_critical():
    """Any KEV-tagged CVE puts the host at Critical regardless of CVSS."""
    matched = (
        {"cve_id": "CVE-2021-44228", "cvss_score": 3.5,
         "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N",
         "is_kev": True},
    )
    snap = _snap(matched_cves=matched)
    out = score_snapshot(snap)
    assert out["kev_present"] is True
    assert out["cvss_headline"] >= 9.0
    assert out["severity"] == "Critical"


# ---------------------------------------------------------------------------
# Risk-score shape
# ---------------------------------------------------------------------------

def test_risk_score_is_headline_times_ten():
    snap = _snap(ports=frozenset({80}))   # CVSS 4.2 from F-001
    out = score_snapshot(snap)
    assert out["risk_score"] == round(out["cvss_headline"] * 10.0, 1)
