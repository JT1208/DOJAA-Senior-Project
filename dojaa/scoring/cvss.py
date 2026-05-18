"""CVSS v3.1 Base Score implementation.

Per the official FIRST.org specification:
https://www.first.org/cvss/v3-1/specification-document
https://www.first.org/cvss/v3-1/cvss-v31-specification_r1.pdf

Only the **Base** metric group is implemented (sufficient for asset
risk assessment without environmental tailoring). Temporal and
Environmental metrics can be layered on later without changing the
public API.

The numeric tables and formulas below match the specification verbatim
— they are not heuristics. Equivalence to the FIRST.org online
calculator is verified by the unit tests in ``tests/test_cvss.py``.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Per-spec metric weights
# ---------------------------------------------------------------------------

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}  # Attack Vector
_AC = {"L": 0.77, "H": 0.44}                         # Attack Complexity
_UI = {"N": 0.85, "R": 0.62}                         # User Interaction
_S = {"U": "unchanged", "C": "changed"}             # Scope

# Privileges Required depends on Scope:
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}

# Confidentiality / Integrity / Availability impact:
_CIA = {"N": 0.00, "L": 0.22, "H": 0.56}

_VALID_METRICS = {
    "AV": set(_AV), "AC": set(_AC), "PR": {"N", "L", "H"},
    "UI": set(_UI),  "S": set(_S),  "C": set(_CIA),
    "I":  set(_CIA), "A": set(_CIA),
}

_REQUIRED_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

_VECTOR_PREFIX = "CVSS:3.1/"


class CvssError(ValueError):
    """Raised when a CVSS vector is malformed."""


@dataclass(frozen=True)
class Cvss31:
    """Parsed CVSS v3.1 Base vector."""

    AV: str
    AC: str
    PR: str
    UI: str
    S: str
    C: str
    I: str
    A: str

    @property
    def vector(self) -> str:
        return (
            _VECTOR_PREFIX
            + f"AV:{self.AV}/AC:{self.AC}/PR:{self.PR}/UI:{self.UI}"
            + f"/S:{self.S}/C:{self.C}/I:{self.I}/A:{self.A}"
        )

    @property
    def base_score(self) -> float:
        return base_score(self)

    @property
    def severity(self) -> str:
        return severity_from_score(self.base_score)


# ---------------------------------------------------------------------------
# Vector parsing
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"^([A-Za-z]+):([A-Za-z])$")


def parse_vector(vector: str) -> Cvss31:
    """Parse a ``CVSS:3.1/AV:…/AC:…/…`` string into a :class:`Cvss31`."""
    if not isinstance(vector, str):
        raise CvssError(f"vector must be a string, got {type(vector).__name__}")
    v = vector.strip()
    if not v.startswith(_VECTOR_PREFIX):
        raise CvssError(f"vector must start with '{_VECTOR_PREFIX}'")
    body = v[len(_VECTOR_PREFIX):]
    out: dict[str, str] = {}
    for tok in body.split("/"):
        m = _TOKEN_RE.match(tok)
        if not m:
            raise CvssError(f"malformed token: {tok!r}")
        key, value = m.group(1), m.group(2).upper()
        if key not in _VALID_METRICS:
            raise CvssError(f"unknown metric: {key}")
        if value not in _VALID_METRICS[key]:
            raise CvssError(f"invalid value for {key}: {value}")
        out[key] = value
    missing = [m for m in _REQUIRED_METRICS if m not in out]
    if missing:
        raise CvssError(f"missing required metrics: {','.join(missing)}")
    return Cvss31(**{m: out[m] for m in _REQUIRED_METRICS})


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _roundup(value: float) -> float:
    """CVSS v3.1 specification rounding ("Roundup1") — ceiling to one decimal."""
    return math.ceil(value * 10) / 10.0


def base_score(c: Cvss31) -> float:
    """Compute the CVSS v3.1 Base Score per spec §7.1."""
    av = _AV[c.AV]
    ac = _AC[c.AC]
    ui = _UI[c.UI]
    pr_table = _PR_CHANGED if c.S == "C" else _PR_UNCHANGED
    pr = pr_table[c.PR]
    confidentiality = _CIA[c.C]
    integrity = _CIA[c.I]
    availability = _CIA[c.A]

    iss = 1.0 - ((1.0 - confidentiality) * (1.0 - integrity) * (1.0 - availability))
    if c.S == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if c.S == "U":
        raw = min(impact + exploitability, 10.0)
    else:
        raw = min(1.08 * (impact + exploitability), 10.0)
    return _roundup(raw)


# ---------------------------------------------------------------------------
# Severity bands
# ---------------------------------------------------------------------------

def severity_from_score(score: float) -> str:
    """Return the qualitative severity band per CVSS v3.1 §5.

    Bands:
        None     0.0
        Low      0.1 — 3.9
        Medium   4.0 — 6.9
        High     7.0 — 8.9
        Critical 9.0 — 10.0
    """
    if score is None:
        return "Unknown"
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "Unknown"
    if s <= 0:
        return "None"
    if s < 4.0:
        return "Low"
    if s < 7.0:
        return "Medium"
    if s < 9.0:
        return "High"
    return "Critical"


def severity_class(severity: str) -> str:
    """Return the badge CSS class for a severity string."""
    s = (severity or "").strip().lower()
    return {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "none": "unknown",
    }.get(s, "unknown")
