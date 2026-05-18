"""Banner parsing → vendor / product / version + CPE 2.3.

The output of this module feeds:

* the risk engine (which uses ``banner_version`` and EOL-product flags)
* the CVE collector (which uses ``cpe`` for precise NVD queries — far
  more accurate than free-text keyword search)
* the UI (which renders ``summary`` next to each row)

The fingerprint table is loosely modelled on Rapid7's Recog
project (https://github.com/rapid7/recog) — when a banner pattern hits,
we emit the canonical (vendor, product) pair NIST/NVD uses in its CPE
dictionary so downstream lookups match the official catalog.

CPE 2.3 reference: https://nvd.nist.gov/products/cpe
NIST IR 7695 (CPE Naming): https://csrc.nist.gov/pubs/ir/7695/final
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Fingerprint table
# ---------------------------------------------------------------------------

# Each entry: (compiled_regex, vendor, product, service_label, kind)
# ``kind`` is 'a' (application), 'o' (os), or 'h' (hardware) per CPE 2.3.
# A capture group named ``v`` extracts the version.

@dataclass(frozen=True)
class _Sig:
    pattern: re.Pattern
    vendor: str
    product: str
    service: str
    kind: str = "a"


def _p(rx: str) -> re.Pattern:
    return re.compile(rx, re.IGNORECASE)


_SSH_SIGNATURES: tuple[_Sig, ...] = (
    _Sig(_p(r"SSH-\d\.\d-OpenSSH[_/\- ]?(?P<v>\d+\.\d+(?:p\d+)?)"),
         "openbsd", "openssh", "SSH"),
    _Sig(_p(r"SSH-\d\.\d-dropbear[_/\- ]?(?P<v>\d+\.\d+)"),
         "matt_johnston", "dropbear_ssh", "SSH"),
    _Sig(_p(r"SSH-\d\.\d-libssh[_/\- ]?(?P<v>\d+\.\d+(?:\.\d+)?)"),
         "libssh", "libssh", "SSH"),
)

_HTTP_SERVER_SIGNATURES: tuple[_Sig, ...] = (
    # Apache + variants
    _Sig(_p(r"Apache(?:/(?P<v>\d+\.\d+(?:\.\d+)?))?\b"),
         "apache", "http_server", "HTTP"),
    # nginx
    _Sig(_p(r"nginx(?:/(?P<v>\d+\.\d+(?:\.\d+)?))?"),
         "nginx", "nginx", "HTTP"),
    # Microsoft IIS
    _Sig(_p(r"Microsoft-IIS/(?P<v>\d+\.\d+)"),
         "microsoft", "internet_information_services", "HTTP"),
    # lighttpd
    _Sig(_p(r"lighttpd/(?P<v>\d+\.\d+(?:\.\d+)?)"),
         "lighttpd", "lighttpd", "HTTP"),
    # Caddy
    _Sig(_p(r"Caddy(?:/(?P<v>\d+\.\d+(?:\.\d+)?))?"),
         "caddyserver", "caddy", "HTTP"),
    # Tomcat
    _Sig(_p(r"(?:Apache )?Tomcat(?:/(?P<v>\d+\.\d+(?:\.\d+)?))?"),
         "apache", "tomcat", "HTTP"),
    # Jetty
    _Sig(_p(r"Jetty\((?P<v>\d+\.\d+(?:\.\d+)?)"),
         "eclipse", "jetty", "HTTP"),
    # Cloudflare reverse proxy
    _Sig(_p(r"cloudflare\b"),
         "cloudflare", "cloudflare", "HTTP"),
    # Amazon
    _Sig(_p(r"AmazonS3|AwsElb|CloudFront"),
         "amazon", "amazon_web_services", "HTTP"),
    # Generic gunicorn / uvicorn / kestrel / werkzeug
    _Sig(_p(r"gunicorn/(?P<v>\d+\.\d+(?:\.\d+)?)"),
         "gunicorn", "gunicorn", "HTTP"),
    _Sig(_p(r"uvicorn"), "encode", "uvicorn", "HTTP"),
    _Sig(_p(r"Werkzeug/(?P<v>\d+\.\d+(?:\.\d+)?)"),
         "pallets", "werkzeug", "HTTP"),
    _Sig(_p(r"Kestrel"), "microsoft", "kestrel", "HTTP"),
)

_FTP_SIGNATURES: tuple[_Sig, ...] = (
    _Sig(_p(r"vsftpd[/\s](?P<v>\d+\.\d+(?:\.\d+)?)"),
         "vsftpd", "vsftpd", "FTP"),
    _Sig(_p(r"ProFTPD[/\s](?P<v>\d+\.\d+(?:\.\d+)?)"),
         "proftpd", "proftpd", "FTP"),
    _Sig(_p(r"Pure-FTPd"), "pureftpd", "pure-ftpd", "FTP"),
    _Sig(_p(r"FileZilla Server[/\s](?P<v>\d+\.\d+(?:\.\d+)?)"),
         "filezilla-project", "filezilla_server", "FTP"),
    _Sig(_p(r"Microsoft FTP Service"), "microsoft", "ftp_service", "FTP"),
)

_MAIL_SIGNATURES: tuple[_Sig, ...] = (
    _Sig(_p(r"Postfix"), "postfix", "postfix", "SMTP"),
    _Sig(_p(r"Exim[\s/]?(?P<v>\d+\.\d+)?"), "exim", "exim", "SMTP"),
    _Sig(_p(r"Sendmail[\s/]?(?P<v>\d+\.\d+(?:\.\d+)?)?"),
         "sendmail", "sendmail", "SMTP"),
    _Sig(_p(r"Microsoft ESMTP MAIL Service"), "microsoft", "exchange_server", "SMTP"),
    _Sig(_p(r"Dovecot"), "dovecot", "dovecot", "IMAP"),
)

_DB_SIGNATURES: tuple[_Sig, ...] = (
    _Sig(_p(r"MySQL[\s/]?(?P<v>\d+\.\d+(?:\.\d+)?)?"), "oracle", "mysql", "MySQL"),
    _Sig(_p(r"MariaDB[\s/]?(?P<v>\d+\.\d+(?:\.\d+)?)?"), "mariadb", "mariadb", "MySQL"),
    _Sig(_p(r"PostgreSQL[\s/]?(?P<v>\d+\.\d+(?:\.\d+)?)?"),
         "postgresql", "postgresql", "PostgreSQL"),
    _Sig(_p(r"Redis[\s/]?(?P<v>\d+\.\d+(?:\.\d+)?)?"), "redis", "redis", "Redis"),
    _Sig(_p(r"MongoDB[\s/]?(?P<v>\d+\.\d+(?:\.\d+)?)?"),
         "mongodb", "mongodb", "MongoDB"),
)

_OS_SIGNATURES: tuple[_Sig, ...] = (
    _Sig(_p(r"Ubuntu[\s\-]?(?P<v>\d+\.\d+)?"), "canonical", "ubuntu_linux", "Ubuntu", "o"),
    _Sig(_p(r"Debian[\s\-]?(?P<v>\d+(?:\.\d+)?)?"), "debian", "debian_linux", "Debian", "o"),
    _Sig(_p(r"CentOS[\s\-]?(?P<v>\d+(?:\.\d+)?)?"), "centos", "centos", "CentOS", "o"),
    _Sig(_p(r"Red Hat|RHEL"), "redhat", "enterprise_linux", "RHEL", "o"),
)

_ALL_SIGNATURES: tuple[_Sig, ...] = (
    _SSH_SIGNATURES + _FTP_SIGNATURES + _MAIL_SIGNATURES +
    _DB_SIGNATURES + _HTTP_SERVER_SIGNATURES + _OS_SIGNATURES
)


# ---------------------------------------------------------------------------
# CPE 2.3 builder
# ---------------------------------------------------------------------------

def _cpe23(vendor: str, product: str, version: str | None, kind: str = "a") -> str:
    """Build a CPE 2.3 string.

    Format: ``cpe:2.3:<part>:<vendor>:<product>:<version>:*:*:*:*:*:*:*``
    Per NIST IR 7695 §6.2. Empty/unknown components are encoded as ``*``.
    """
    def fld(v: str | None) -> str:
        if not v:
            return "*"
        return re.sub(r"\s+", "_", v.strip().lower())
    return f"cpe:2.3:{kind}:{fld(vendor)}:{fld(product)}:{fld(version)}:*:*:*:*:*:*:*"


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Parsed:
    service: str
    vendor: str | None
    product: str | None
    version: str | None
    cpe: str | None
    summary: str
    raw_match: str | None = None


def _port_default(port: int | None) -> tuple[str, str]:
    port_map = {
        22: ("SSH", "SSH service detected"),
        21: ("FTP", "FTP service detected"),
        23: ("Telnet", "Telnet (cleartext) service detected"),
        25: ("SMTP", "Mail transport service detected"),
        80: ("HTTP", "HTTP service detected"),
        110: ("POP3", "POP3 mail service detected"),
        143: ("IMAP", "IMAP mail service detected"),
        443: ("HTTPS", "HTTPS service detected"),
        465: ("SMTPS", "Encrypted SMTP service detected"),
        587: ("SMTP-Submission", "SMTP submission service detected"),
        993: ("IMAPS", "Encrypted IMAP service detected"),
        995: ("POP3S", "Encrypted POP3 service detected"),
        3306: ("MySQL", "MySQL/MariaDB service detected"),
        3389: ("RDP", "Remote Desktop service detected"),
        5432: ("PostgreSQL", "PostgreSQL service detected"),
        5900: ("VNC", "VNC service detected"),
        6379: ("Redis", "Redis service detected"),
        9200: ("Elasticsearch", "Elasticsearch service detected"),
        27017: ("MongoDB", "MongoDB service detected"),
    }
    return port_map.get(int(port) if port is not None else -1, ("Unknown", "Service detected"))


def _format_summary(p: Parsed) -> str:
    label = p.product.replace("_", " ").title() if p.product else p.service
    if p.version:
        return f"{label} {p.version}"
    return f"{label}"


def parse_banner(banner: str, port: int | None = None) -> dict:
    """Return parsed fingerprint metadata for a service banner.

    The return dict matches the legacy contract used by the rest of the
    pipeline (``service``, ``product``, ``version``, ``summary``) and
    adds ``vendor``, ``cpe``, ``raw_match`` for downstream consumers.
    """
    text = banner or ""

    # Look at the most informative line of the banner for fingerprinting
    candidate = text
    server_match = re.search(r"server:\s*([^\r\n]+)", text, re.IGNORECASE)
    if server_match:
        candidate = server_match.group(1).strip()

    # First-match wins; signatures are ordered by specificity.
    for sig in _ALL_SIGNATURES:
        m = sig.pattern.search(candidate) or sig.pattern.search(text)
        if not m:
            continue
        version = None
        if "v" in sig.pattern.groupindex:
            version = (m.groupdict().get("v") or "").strip() or None
        cpe = _cpe23(sig.vendor, sig.product, version, sig.kind)
        parsed = Parsed(
            service=sig.service,
            vendor=sig.vendor,
            product=sig.product,
            version=version,
            cpe=cpe,
            summary="",
            raw_match=m.group(0),
        )
        parsed = Parsed(
            service=parsed.service, vendor=parsed.vendor,
            product=parsed.product, version=parsed.version,
            cpe=parsed.cpe,
            summary=_format_summary(parsed),
            raw_match=parsed.raw_match,
        )
        return {
            "service":   parsed.service,
            "vendor":    parsed.vendor,
            "product":   parsed.product,
            "version":   parsed.version,
            "cpe":       parsed.cpe,
            "summary":   parsed.summary,
            "raw_match": parsed.raw_match,
        }

    # Fallback by well-known port
    label, summary = _port_default(port)
    return {
        "service":   label,
        "vendor":    None,
        "product":   None,
        "version":   None,
        "cpe":       None,
        "summary":   summary,
        "raw_match": None,
    }


# ---------------------------------------------------------------------------
# CVE keyword fallback
# ---------------------------------------------------------------------------

def cve_keyword(parsed: dict) -> str | None:
    """Build the highest-fidelity NVD ``keywordSearch`` string for a parsed
    banner. Used when the CPE-based query falls through.
    """
    vendor = parsed.get("vendor")
    product = parsed.get("product")
    version = parsed.get("version")
    parts: list[str] = []
    if vendor and vendor != product:
        parts.append(vendor.replace("_", " "))
    if product:
        parts.append(product.replace("_", " "))
    if version:
        parts.append(version)
    if not parts:
        return None
    return " ".join(parts)
