"""CVSS v3.1 calculator — verified against FIRST.org reference values.

Each row in :data:`PUBLISHED_CASES` is sourced from real CVE records or
the FIRST online calculator (https://www.first.org/cvss/calculator/3.1).
The implementation in :mod:`dojaa.scoring.cvss` must reproduce the
exact base score and severity band for every row, byte for byte.
"""

from __future__ import annotations

import pytest

from dojaa.scoring.cvss import (
    Cvss31,
    CvssError,
    base_score,
    parse_vector,
    severity_from_score,
)


# Vector, expected base score, expected severity.
# All sourced from NVD's published CVSS records or the FIRST calculator.
PUBLISHED_CASES = [
    # Heartbleed — CVE-2014-0160 (NVD: 7.5, High)
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "High"),

    # Shellshock-class network unauth RCE (NVD typical 9.8)
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),

    # Local privilege escalation
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "High"),

    # Stored XSS — scope changed
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4, "Medium"),

    # Info disclosure (banner)
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "Medium"),

    # SSH service exposed (low impact across CIA)
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", 7.3, "High"),

    # Edge: zero score
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "None"),

    # High complexity, requires high privilege
    ("CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H", 6.6, "Medium"),

    # Adjacent network, low complexity, no privileges
    ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", 6.3, "Medium"),

    # Physical attack vector
    ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 6.8, "Medium"),
]


@pytest.mark.parametrize("vector,score,severity", PUBLISHED_CASES)
def test_cvss_matches_published_values(vector, score, severity):
    parsed = parse_vector(vector)
    assert base_score(parsed) == score
    assert severity_from_score(score) == severity


def test_vector_round_trip():
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    parsed = parse_vector(v)
    assert parsed.vector == v


def test_severity_bands_boundaries():
    # Boundary values per CVSS v3.1 §5.
    assert severity_from_score(0.0) == "None"
    assert severity_from_score(0.1) == "Low"
    assert severity_from_score(3.9) == "Low"
    assert severity_from_score(4.0) == "Medium"
    assert severity_from_score(6.9) == "Medium"
    assert severity_from_score(7.0) == "High"
    assert severity_from_score(8.9) == "High"
    assert severity_from_score(9.0) == "Critical"
    assert severity_from_score(10.0) == "Critical"


def test_malformed_vector_raises():
    with pytest.raises(CvssError):
        parse_vector("not a vector")
    with pytest.raises(CvssError):
        parse_vector("CVSS:3.1/AV:N/AC:L")          # missing metrics
    with pytest.raises(CvssError):
        parse_vector("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")  # invalid AV


def test_cvss31_dataclass_immutable():
    c = Cvss31(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H")
    assert c.base_score == 9.8
    assert c.severity == "Critical"
    with pytest.raises(Exception):
        c.AV = "L"  # frozen
