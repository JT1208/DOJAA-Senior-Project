"""Findings catalog — each spec is well-formed and behaves as documented.

We assert two things per finding:

1. The catalog metadata is valid (parseable CVSS vector, valid CWE id,
   non-empty references, non-empty remediation).
2. The matcher fires on a representative *positive* host and stays
   quiet on an unambiguously *negative* host.
"""

from __future__ import annotations

import pytest

from dojaa.scoring.cvss import parse_vector
from dojaa.scoring.findings import (
    CATALOG,
    HostSnapshot,
    evaluate_findings,
    get,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _snap(ip="1.2.3.4", ports=(), services=(), banners=(),
          known=True, matched_cves=(), tls_certs=()) -> HostSnapshot:
    return HostSnapshot(
        ip=ip,
        ports=frozenset(ports),
        services=tuple(services),
        banners=tuple(banners),
        known=known,
        matched_cves=tuple(matched_cves),
        tls_certs=tuple(tls_certs),
    )


# ---------------------------------------------------------------------------
# Catalog hygiene
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("spec", CATALOG, ids=lambda s: s.id)
def test_catalog_metadata_well_formed(spec):
    assert spec.id.startswith("DOJAA-FNDG-"), spec.id
    assert spec.title
    assert spec.description.strip()
    assert spec.cwe_id.upper().startswith("CWE-")
    assert spec.cwe_name
    parse_vector(spec.cvss_vector)       # raises CvssError if invalid
    assert spec.cvss_score > 0.0
    assert spec.severity in {"None", "Low", "Medium", "High", "Critical"}
    for ctrl in spec.nist_controls:
        # SP 800-53 control IDs look like AA-NN[(N)] or AA-NN[(N)]
        assert "-" in ctrl, ctrl
    assert spec.references, "every finding needs at least one citation"
    assert spec.remediation.strip()


def test_catalog_ids_are_unique():
    ids = [s.id for s in CATALOG]
    assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# Matcher behaviour
# ---------------------------------------------------------------------------

def test_cleartext_http_fires_when_only_80():
    snap = _snap(ports={80})
    titles = {f["title"] for f in evaluate_findings(snap)}
    assert "Cleartext HTTP service without TLS" in titles


def test_cleartext_http_silent_when_443_also_open():
    snap = _snap(ports={80, 443})
    titles = {f["title"] for f in evaluate_findings(snap)}
    assert "Cleartext HTTP service without TLS" not in titles


def test_ssh_exposed_fires_only_for_port_22():
    assert any(
        f["id"] == "DOJAA-FNDG-002"
        for f in evaluate_findings(_snap(ports={22}))
    )
    assert not any(
        f["id"] == "DOJAA-FNDG-002"
        for f in evaluate_findings(_snap(ports={80}))
    )


def test_banner_version_fires_when_any_service_has_version():
    snap = _snap(services=({"banner_version": "1.2.3"},))
    assert any(f["id"] == "DOJAA-FNDG-003" for f in evaluate_findings(snap))


def test_shadow_silent_when_known_is_none():
    snap = _snap(known=None)
    assert not any(f["id"] == "DOJAA-FNDG-008" for f in evaluate_findings(snap))


def test_shadow_fires_when_known_is_false():
    snap = _snap(known=False)
    assert any(f["id"] == "DOJAA-FNDG-008" for f in evaluate_findings(snap))


def test_eol_openssh_detected_in_banner():
    snap = _snap(banners=("SSH-2.0-OpenSSH_7.4 Debian-10",))
    assert any(f["id"] == "DOJAA-FNDG-004" for f in evaluate_findings(snap))


def test_apache_22_detected():
    snap = _snap(banners=("Server: Apache/2.2.15 (CentOS)",))
    assert any(f["id"] == "DOJAA-FNDG-005" for f in evaluate_findings(snap))


def test_openssl_1_0_detected():
    snap = _snap(banners=("OpenSSL/1.0.2k-fips mod_perl/2.0.11",))
    assert any(f["id"] == "DOJAA-FNDG-006" for f in evaluate_findings(snap))


def test_sensitive_port_fires_for_3389():
    snap = _snap(ports={3389})
    assert any(f["id"] == "DOJAA-FNDG-007" for f in evaluate_findings(snap))


def test_expired_cert_fires():
    snap = _snap(tls_certs=({"days_left": -5},))
    assert any(f["id"] == "DOJAA-FNDG-009" for f in evaluate_findings(snap))


def test_expiring_soon_fires_under_30_days():
    snap = _snap(tls_certs=({"days_left": 12},))
    titles = {f["id"] for f in evaluate_findings(snap)}
    assert "DOJAA-FNDG-010" in titles
    assert "DOJAA-FNDG-009" not in titles  # not expired yet


def test_self_signed_cert_fires():
    snap = _snap(tls_certs=({"trust": "Dev / Default Cert"},))
    assert any(f["id"] == "DOJAA-FNDG-011" for f in evaluate_findings(snap))


def test_cves_match_fires_when_any_matched():
    snap = _snap(matched_cves=({"cve_id": "CVE-2020-0000"},))
    assert any(f["id"] == "DOJAA-FNDG-012" for f in evaluate_findings(snap))


def test_kev_fires_only_when_is_kev_true():
    pos = _snap(matched_cves=({"cve_id": "CVE-2021-44228", "is_kev": True},))
    neg = _snap(matched_cves=({"cve_id": "CVE-2021-44228", "is_kev": False},))
    assert any(f["id"] == "DOJAA-FNDG-013" for f in evaluate_findings(pos))
    assert not any(f["id"] == "DOJAA-FNDG-013" for f in evaluate_findings(neg))


def test_get_returns_known_spec():
    assert get("DOJAA-FNDG-001") is not None
    assert get("DOJAA-FNDG-999") is None
