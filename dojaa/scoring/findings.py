"""Official-grade findings catalog.

Every finding emitted by the risk engine is grounded in a recognised
framework so the output is defensible to an auditor:

* **CWE** — MITRE Common Weakness Enumeration  (https://cwe.mitre.org/)
* **CVSS v3.1** — FIRST.org Common Vulnerability Scoring System
  (https://www.first.org/cvss/)
* **NIST SP 800-53 Rev. 5** — Security & Privacy Controls
  (https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
* **MITRE ATT&CK** Enterprise — Adversary techniques
  (https://attack.mitre.org/)
* **CISA KEV** — Known Exploited Vulnerabilities Catalog
  (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

Each finding carries:

- a stable identifier (DOJAA-FNDG-NNN)
- a representative CVSS v3.1 base vector (audited against FIRST.org
  online calculator — the catalog test suite asserts the score)
- list of NIST 800-53 control IDs that mitigate it
- list of MITRE ATT&CK technique IDs it enables
- authoritative references the reader can verify
- a remediation paragraph
- an evaluator callable that returns True iff the finding applies to a
  given host snapshot

The engine never emits a finding that isn't in this file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .cvss import Cvss31, parse_vector, severity_from_score


# ---------------------------------------------------------------------------
# Per-host evaluation context
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HostSnapshot:
    """Everything the catalog needs to decide which findings apply to a host.

    The pipeline builds one of these per unique IP and hands it to
    :func:`evaluate_findings`. Fields are kept primitive so the snapshot
    serialises cleanly for caching and so unit tests can construct one
    in a single statement.
    """

    ip: str
    ports: frozenset[int]
    services: tuple[dict, ...]
    banners: tuple[str, ...]
    known: bool | None
    matched_cves: tuple[dict, ...] = ()
    tls_certs: tuple[dict, ...] = ()

    @property
    def has_https(self) -> bool:
        return 443 in self.ports

    @property
    def has_http(self) -> bool:
        return 80 in self.ports

    @property
    def has_ssh(self) -> bool:
        return 22 in self.ports

    def banner_text(self) -> str:
        return "\n".join(b for b in self.banners if b).lower()


# ---------------------------------------------------------------------------
# Finding definition
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FindingSpec:
    """Authoritative description of one possible finding.

    The ``category`` decides whether a finding contributes to the host's
    headline CVSS:

    * ``vulnerability`` — confirmed exploitable weakness (EOL software,
      expired cert). Contributes to the headline.
    * ``cve``           — direct NVD match. Contributes; its CVSS comes
      from the worst matched CVE at scoring time, not from the static
      vector below.
    * ``exposure``      — service is reachable. Listed but does NOT
      drive headline CVSS, because reachability ≠ exploitability.
    * ``hardening``     — best-practice gap (banner disclosure, shadow
      asset). Listed; does not drive headline CVSS.

    The category split prevents two unrelated "posture" observations
    from compounding into a CVSS-band promotion. Industry tools
    (Tenable, Qualys, Rapid7) follow the same convention.
    """

    id: str
    title: str
    description: str
    cwe_id: str               # e.g. "CWE-319"
    cwe_name: str
    cvss_vector: str          # CVSS:3.1/...
    nist_controls: tuple[str, ...]    # e.g. ("SC-8", "SC-23")
    mitre_techniques: tuple[str, ...] # e.g. ("T1040",)
    references: tuple[tuple[str, str], ...]  # (title, url)
    remediation: str
    matches: Callable[[HostSnapshot], bool] = field(repr=False)
    category: str = "vulnerability"

    # -- computed --------------------------------------------------------

    @property
    def cvss(self) -> Cvss31:
        return parse_vector(self.cvss_vector)

    @property
    def cvss_score(self) -> float:
        return self.cvss.base_score

    @property
    def severity(self) -> str:
        return severity_from_score(self.cvss_score)

    def cwe_url(self) -> str:
        n = self.cwe_id.split("-", 1)[-1]
        return f"https://cwe.mitre.org/data/definitions/{n}.html"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "cwe": {"id": self.cwe_id, "name": self.cwe_name, "url": self.cwe_url()},
            "cvss": {
                "vector": self.cvss_vector,
                "score": self.cvss_score,
                "severity": self.severity,
            },
            "nist_controls": list(self.nist_controls),
            "mitre_techniques": list(self.mitre_techniques),
            "references": [{"title": t, "url": u} for t, u in self.references],
            "remediation": self.remediation,
        }


# ---------------------------------------------------------------------------
# Detector helpers
# ---------------------------------------------------------------------------

import re

_RE_OPENSSH = re.compile(r"openssh[_/\-]?(\d+)(?:\.(\d+))?")
_RE_APACHE  = re.compile(r"apache(?:[/\s])?(\d+)(?:\.(\d+))?")
_RE_OPENSSL = re.compile(r"openssl[/\s]?(\d+)(?:\.(\d+))?(?:\.(\d+))?")
_RE_NGINX_OLD = re.compile(r"nginx[/\s](\d+)(?:\.(\d+))?")

_END_OF_LIFE_OPENSSH = {6, 7}      # 7.x last released 2019; 8.x is current LTS
_END_OF_LIFE_APACHE  = {1, 2}      # only 2.4 is supported; flag 2.0/2.2 below
_END_OF_LIFE_OPENSSL = {(0, ), (1, 0)}  # 0.x, 1.0.x are EOL


def _has_openssh_eol(text: str) -> bool:
    m = _RE_OPENSSH.search(text)
    if not m:
        return False
    major = int(m.group(1))
    return major in _END_OF_LIFE_OPENSSH


def _has_apache_22(text: str) -> bool:
    return bool(re.search(r"apache[/\s]2\.2(?:\.|$|\D)", text))


def _has_openssl_1_0(text: str) -> bool:
    return bool(re.search(r"openssl[/\s]1\.0(?:\.|$|\D)", text))


def _has_banner_version(snap: HostSnapshot) -> bool:
    """True iff any service exposes a vendor/version triple in its banner."""
    for svc in snap.services:
        if svc.get("banner_version"):
            return True
    return False


_SENSITIVE_PORTS = {
    21:   ("FTP",          "Cleartext file transfer; replace with SFTP/FTPS."),
    23:   ("Telnet",       "Cleartext remote shell; replace with SSH."),
    25:   ("SMTP",         "Mail relay; require STARTTLS + authentication."),
    110:  ("POP3",         "Cleartext mail retrieval; require POP3S."),
    143:  ("IMAP",         "Cleartext mail retrieval; require IMAPS."),
    3306: ("MySQL/MariaDB","DB engine; must not be public-facing."),
    3389: ("RDP",          "Remote desktop; require VPN + NLA + MFA."),
    5900: ("VNC",          "Remote desktop; require VPN + strong auth."),
    6379: ("Redis",        "Key-value store; must not be public-facing."),
    27017:("MongoDB",      "Document store; must not be public-facing."),
}


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------

CATALOG: tuple[FindingSpec, ...] = (

    FindingSpec(
        id="DOJAA-FNDG-001",
        title="Cleartext HTTP service without TLS",
        description=(
            "A web service is reachable over plaintext HTTP and the host "
            "does not also expose HTTPS. Credentials, session tokens, and "
            "page contents travel in the clear and can be intercepted on "
            "any path between the client and the server."
        ),
        category="vulnerability",
        cwe_id="CWE-319",
        cwe_name="Cleartext Transmission of Sensitive Information",
        # AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N — interception requires being
        # on-path (AC:H) and a user actually transmitting sensitive data (UI:R).
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        nist_controls=("SC-8", "SC-8(1)", "SC-23"),
        mitre_techniques=("T1040",),  # Network Sniffing
        references=(
            ("CWE-319", "https://cwe.mitre.org/data/definitions/319.html"),
            ("NIST SP 800-52 Rev. 2 (TLS guidelines)",
             "https://csrc.nist.gov/pubs/sp/800/52/r2/final"),
            ("OWASP ASVS V9: Communications",
             "https://owasp.org/www-project-application-security-verification-standard/"),
        ),
        remediation=(
            "Serve traffic exclusively over HTTPS using a publicly-trusted "
            "certificate (Let's Encrypt is free). Redirect 80 → 443 with "
            "HTTP 301 and set the HSTS header (Strict-Transport-Security) "
            "with a max-age of at least one year and includeSubDomains."
        ),
        matches=lambda s: s.has_http and not s.has_https,
    ),

    FindingSpec(
        id="DOJAA-FNDG-002",
        title="SSH service exposed to the public internet",
        description=(
            "Port 22 is reachable from the public internet. SSH itself is "
            "designed to be safe to expose when hardened, so this finding "
            "is informational — it widens the attacker's footprint and "
            "creates a constant brute-force / credential-stuffing surface, "
            "but is not by itself an exploitable weakness."
        ),
        category="exposure",   # ← does not drive headline CVSS
        cwe_id="CWE-284",
        cwe_name="Improper Access Control",
        # AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N — exposure alone has only
        # confidentiality-low risk (recon / username enumeration in poor
        # configs). Real impact only materialises if auth is weak.
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        nist_controls=("AC-3", "AC-17", "SC-7", "SC-7(3)"),
        mitre_techniques=("T1110", "T1078"),  # Brute Force; Valid Accounts
        references=(
            ("CWE-284", "https://cwe.mitre.org/data/definitions/284.html"),
            ("NIST SP 800-46 (Remote Access)",
             "https://csrc.nist.gov/pubs/sp/800/46/r2/final"),
        ),
        remediation=(
            "Place SSH behind a VPN or an identity-aware proxy. If direct "
            "exposure is unavoidable, restrict source IPs via firewall, "
            "disable password authentication (PasswordAuthentication no), "
            "and require multi-factor authentication."
        ),
        matches=lambda s: s.has_ssh,
    ),

    FindingSpec(
        id="DOJAA-FNDG-003",
        title="Service version disclosed in banner",
        description=(
            "The service banner advertises a precise vendor + version "
            "string. Public vulnerability databases (NVD) and exploit "
            "frameworks (Metasploit) consume those strings directly, "
            "lowering the effort an attacker needs for reconnaissance."
        ),
        category="hardening",   # ← does not drive headline CVSS
        cwe_id="CWE-200",
        cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
        # AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N = 5.3, but reality is
        # closer to "informational" — NVD only scores banner leaks when
        # they enable concrete enumeration. We use AC:H to reflect that.
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        nist_controls=("SI-11", "AC-23"),
        mitre_techniques=("T1592", "T1595.002"),  # Gather host info; Active scanning
        references=(
            ("CWE-200", "https://cwe.mitre.org/data/definitions/200.html"),
        ),
        remediation=(
            "Suppress version strings: Apache 'ServerTokens Prod', nginx "
            "'server_tokens off', sshd 'DebianBanner no', etc. Strip the "
            "'Server' header at the reverse proxy."
        ),
        matches=_has_banner_version,
    ),

    FindingSpec(
        id="DOJAA-FNDG-004",
        title="End-of-life OpenSSH version (6.x / 7.x)",
        description=(
            "An OpenSSH major version that the upstream project no longer "
            "receives security fixes for is running on this host. Known "
            "CVEs against 7.x (and earlier) are unlikely to be patched in "
            "place; only an upgrade closes them."
        ),
        category="vulnerability",
        cwe_id="CWE-1104",
        cwe_name="Use of Unmaintained Third Party Components",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        nist_controls=("SA-22", "RA-5", "CM-7", "SI-2"),
        mitre_techniques=("T1190",),  # Exploit Public-Facing Application
        references=(
            ("OpenSSH release history", "https://www.openssh.com/releasenotes.html"),
            ("NIST SP 800-40 r4 (Patch Management)",
             "https://csrc.nist.gov/pubs/sp/800/40/r4/final"),
        ),
        remediation=(
            "Upgrade OpenSSH to the current LTS series (9.x). On Debian/"
            "Ubuntu LTS, ensure the security pocket is enabled and run "
            "unattended-upgrades."
        ),
        matches=lambda s: _has_openssh_eol(s.banner_text()),
    ),

    FindingSpec(
        id="DOJAA-FNDG-005",
        title="End-of-life Apache HTTP Server 2.2",
        description=(
            "Apache 2.2 reached end-of-life in July 2017. Subsequent CVEs "
            "are not backported. Any deployment exposing 2.2 to the public "
            "internet is presumed vulnerable to multiple high-severity "
            "issues."
        ),
        category="vulnerability",
        cwe_id="CWE-1104",
        cwe_name="Use of Unmaintained Third Party Components",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        nist_controls=("SA-22", "RA-5", "SI-2"),
        mitre_techniques=("T1190",),
        references=(
            ("Apache 2.2 EOL announcement",
             "https://blogs.apache.org/foundation/entry/announcement_end_of_life_of"),
        ),
        remediation=(
            "Upgrade to the supported 2.4.x series and review configuration "
            "directives that changed between 2.2 and 2.4 (Order/Allow/Deny "
            "→ Require, etc.)."
        ),
        matches=lambda s: _has_apache_22(s.banner_text()),
    ),

    FindingSpec(
        id="DOJAA-FNDG-006",
        title="End-of-life OpenSSL 1.0.x",
        description=(
            "OpenSSL 1.0.x reached end-of-life on 2019-12-31. Notable "
            "issues such as Heartbleed (CVE-2014-0160) and ROBOT live in "
            "this branch. Any service linked against it is presumed "
            "vulnerable."
        ),
        category="vulnerability",
        cwe_id="CWE-1104",
        cwe_name="Use of Unmaintained Third Party Components",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        nist_controls=("SA-22", "RA-5", "SI-2"),
        mitre_techniques=("T1190",),
        references=(
            ("OpenSSL 1.0.2 EOL", "https://www.openssl.org/policies/releasestrat.html"),
            ("Heartbleed CVE-2014-0160", "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"),
        ),
        remediation=(
            "Rebuild and redeploy against OpenSSL 3.x (or the distribution's "
            "current supported branch). Revoke and reissue TLS certificates "
            "that were generated by the vulnerable build."
        ),
        matches=lambda s: _has_openssl_1_0(s.banner_text()),
    ),

    FindingSpec(
        id="DOJAA-FNDG-007",
        title="Sensitive admin/database/legacy port publicly reachable",
        description=(
            "A port that hosts an administrative service, a database "
            "engine, or a legacy cleartext protocol is reachable from the "
            "public internet. These services are designed to be consumed "
            "from inside a trust boundary; full impact materialises only "
            "when authentication is also weak/absent."
        ),
        category="exposure",   # ← reachability ≠ exploitability
        cwe_id="CWE-1390",
        cwe_name="Weak Authentication",
        # AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N = 3.7 Low — a sensible
        # default for "service reachable, configuration unknown". The
        # finding rises naturally if NVD CVEs match the actual product.
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        nist_controls=("AC-3", "AC-4", "SC-7", "SC-7(3)", "CM-7"),
        mitre_techniques=("T1190", "T1078"),
        references=(
            ("CWE-1390", "https://cwe.mitre.org/data/definitions/1390.html"),
            ("CIS Control 13: Network Monitoring & Defense",
             "https://www.cisecurity.org/controls/cis-controls-list"),
        ),
        remediation=(
            "Move the service behind the perimeter (private subnet, VPN, "
            "bastion). At the edge firewall, deny ingress on these ports "
            "by default and audit exceptions."
        ),
        matches=lambda s: bool(s.ports & set(_SENSITIVE_PORTS)),
    ),

    FindingSpec(
        id="DOJAA-FNDG-008",
        title="Shadow asset — discovered outside the known inventory",
        description=(
            "An external recon hit returned a host that does not appear "
            "in the organisation's authoritative asset inventory. Shadow "
            "assets typically arise from forgotten cloud instances, "
            "vendor handoffs, or domain hijacking, and are over-represented "
            "in breach forensics. This is an asset-management gap, not a "
            "vulnerability on its own."
        ),
        category="hardening",   # ← asset-management gap, not a vuln
        cwe_id="CWE-1059",
        cwe_name="Insufficient Technical Documentation",
        # Low (3.7) — inventory gap helps an attacker pick targets.
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        nist_controls=("CM-8", "CM-8(1)", "CM-8(3)", "PM-5"),
        mitre_techniques=("T1190",),
        references=(
            ("NIST SP 800-53 r5 §CM-8 (System Component Inventory)",
             "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final"),
            ("CIS Control 1: Inventory & Control of Enterprise Assets",
             "https://www.cisecurity.org/controls/cis-controls-list"),
        ),
        remediation=(
            "Verify the host's ownership and either bring it under "
            "configuration management or decommission it. Update the "
            "authoritative inventory once resolved."
        ),
        matches=lambda s: s.known is False,
    ),

    FindingSpec(
        id="DOJAA-FNDG-009",
        title="TLS certificate expired",
        description=(
            "A TLS certificate served by this host has already passed its "
            "notAfter date. Modern browsers refuse the connection; clients "
            "configured to override the warning are exposed to active "
            "interception."
        ),
        category="vulnerability",
        cwe_id="CWE-298",
        cwe_name="Improper Validation of Certificate Expiration",
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
        nist_controls=("SC-12", "SC-17"),
        mitre_techniques=("T1557",),  # Adversary-in-the-Middle
        references=(
            ("CWE-298", "https://cwe.mitre.org/data/definitions/298.html"),
            ("CA/Browser Forum Baseline Requirements",
             "https://cabforum.org/baseline-requirements-documents/"),
        ),
        remediation=(
            "Renew or reissue the certificate immediately. Automate renewal "
            "via ACME (certbot, acme.sh) and alarm on certificates within "
            "30 days of expiry."
        ),
        matches=lambda s: any(
            isinstance(c.get("days_left"), int) and c.get("days_left") < 0
            for c in s.tls_certs
        ),
    ),

    FindingSpec(
        id="DOJAA-FNDG-010",
        title="TLS certificate expires within 30 days",
        description=(
            "A certificate is approaching its expiration date. Lack of "
            "automated renewal is a recurring cause of unplanned outages "
            "and ad-hoc certificate replacement under pressure."
        ),
        category="hardening",
        cwe_id="CWE-672",
        cwe_name="Operation on a Resource after Expiration or Release",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
        nist_controls=("SC-12", "SC-17", "CM-2"),
        mitre_techniques=(),
        references=(
            ("ACME RFC 8555", "https://datatracker.ietf.org/doc/html/rfc8555"),
        ),
        remediation=(
            "Automate certificate renewal via ACME. Set up monitoring that "
            "fires at 30 days before notAfter."
        ),
        matches=lambda s: any(
            isinstance(c.get("days_left"), int) and 0 <= c.get("days_left") < 30
            for c in s.tls_certs
        ),
    ),

    FindingSpec(
        id="DOJAA-FNDG-011",
        title="Self-signed or untrusted certificate",
        description=(
            "The certificate is not chained to a publicly-trusted root. "
            "Clients cannot distinguish a legitimate self-signed cert from "
            "an attacker-supplied one, which encourages users to dismiss "
            "browser warnings as routine."
        ),
        category="vulnerability",
        cwe_id="CWE-295",
        cwe_name="Improper Certificate Validation",
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
        nist_controls=("SC-12", "SC-12(3)", "SC-23"),
        mitre_techniques=("T1557",),
        references=(
            ("CWE-295", "https://cwe.mitre.org/data/definitions/295.html"),
        ),
        remediation=(
            "Provision a certificate from a publicly-trusted CA "
            "(Let's Encrypt is free and automated)."
        ),
        matches=lambda s: any(
            (c.get("trust") or "").lower() in ("dev / default cert", "unknown ca", "broken / missing")
            for c in s.tls_certs
        ),
    ),

    FindingSpec(
        id="DOJAA-FNDG-012",
        title="One or more CVEs match a service on this host",
        description=(
            "NVD reports public CVE records whose CPE or keyword matches "
            "a service banner on this host. Each match is a candidate "
            "vulnerability — patch level needs to be verified against the "
            "vendor's advisory. The headline CVSS for this finding is "
            "taken from the worst matched CVE's own NVD score, not from "
            "the static vector below."
        ),
        category="cve",        # ← scoring engine overrides cvss with worst-matched
        cwe_id="CWE-1395",
        cwe_name="Dependency on Vulnerable Third-Party Component",
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        nist_controls=("RA-5", "SI-2", "SI-2(5)"),
        mitre_techniques=("T1190", "T1203"),
        references=(
            ("NVD", "https://nvd.nist.gov/"),
        ),
        remediation=(
            "Cross-reference each matched CVE against the running build's "
            "patch level. Apply vendor-supplied fixes or compensating "
            "controls within the SLA defined by NIST 800-40 §3.4."
        ),
        matches=lambda s: bool(s.matched_cves),
    ),

    FindingSpec(
        id="DOJAA-FNDG-013",
        title="CISA Known Exploited Vulnerability present",
        description=(
            "At least one of the CVEs matched to this host appears in the "
            "CISA Known Exploited Vulnerabilities (KEV) catalog — meaning "
            "CISA has observed active exploitation in the wild. Under BOD "
            "22-01, U.S. federal civilian agencies are required to remediate."
        ),
        category="vulnerability",
        cwe_id="CWE-1395",
        cwe_name="Dependency on Vulnerable Third-Party Component",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        nist_controls=("RA-5", "SI-2", "IR-5"),
        mitre_techniques=("T1190",),
        references=(
            ("CISA KEV catalog",
             "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
            ("CISA BOD 22-01",
             "https://www.cisa.gov/news-events/directives/bod-22-01-reducing-significant-risk-known-exploited-vulnerabilities"),
        ),
        remediation=(
            "Treat as the highest-priority patch on the host. Remediate "
            "within CISA's published due-date; if a patch is not available, "
            "apply CISA's recommended mitigation or remove the service."
        ),
        matches=lambda s: any(c.get("is_kev") for c in s.matched_cves),
    ),
)


_CATALOG_BY_ID: dict[str, FindingSpec] = {f.id: f for f in CATALOG}


def get(finding_id: str) -> FindingSpec | None:
    return _CATALOG_BY_ID.get(finding_id)


def evaluate_findings(snapshot: HostSnapshot) -> list[dict]:
    """Return the list of findings (as dicts) that apply to ``snapshot``."""
    out: list[dict] = []
    for spec in CATALOG:
        try:
            fires = bool(spec.matches(snapshot))
        except Exception:  # noqa: BLE001 — defensive: a buggy matcher
            fires = False                                              # mustn't crash the run
        if not fires:
            continue
        out.append(spec.to_dict())
    return out
