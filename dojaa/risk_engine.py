"""Heuristic risk scoring (0–100) for a normalized asset row.

Risk is scored per (ip, port) row, but a row's exposure flags (SSH /
HTTPS / HTTP-without-HTTPS) only make sense in the context of the
host's full port set — if a host has port 443 listed under one row, the
port-22 row of that same host should not say "No HTTPS protection".

The pipeline therefore calls :func:`calculate_risk` with a
``host_context`` argument summarising the host's full port list. When
``host_context`` is omitted the function falls back to the per-row
``http_exposed`` / ``https_exposed`` / ``ssh_exposed`` flags so the
legacy single-row contract still works.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

_VERSION_RE = re.compile(r"(\d+)(?:\.(\d+))?")
_SENSITIVE_PORTS = {21, 25, 3306, 3389}


def _port_to_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class HostContext:
    """The host-level facts a row needs to score itself accurately."""

    ports: frozenset[int]

    @property
    def has_https(self) -> bool:
        return 443 in self.ports

    @property
    def has_http(self) -> bool:
        return 80 in self.ports

    @property
    def has_ssh(self) -> bool:
        return 22 in self.ports


def build_host_context(rows: Iterable[dict]) -> dict[str, HostContext]:
    """Build a per-IP HostContext from the row stream so the risk engine
    can answer host-level questions ("does this host have any 443 port?").
    """
    ports_by_ip: dict[str, set[int]] = {}
    for row in rows:
        ip = row.get("ip")
        port = _port_to_int(row.get("port"))
        if not ip or port is None:
            continue
        ports_by_ip.setdefault(ip, set()).add(port)
    return {ip: HostContext(ports=frozenset(ports)) for ip, ports in ports_by_ip.items()}


def calculate_risk(asset: dict, host_context: HostContext | None = None) -> dict:
    """Score an asset row 0–100, attaching issues + recommendations."""
    risk_score = 0
    issues: list[str] = []
    recommendations: list[str] = []

    # If no explicit host context, fall back to the row's own flags so this
    # function still works for callers that don't aggregate per host.
    if host_context is None:
        ports: set[int] = set()
        if asset.get("ssh_exposed"):   ports.add(22)
        if asset.get("http_exposed"):  ports.add(80)
        if asset.get("https_exposed"): ports.add(443)
        port_val = _port_to_int(asset.get("port"))
        if port_val is not None:
            ports.add(port_val)
        host_context = HostContext(ports=frozenset(ports))

    row_port = _port_to_int(asset.get("port"))

    # ---------------- BASE EXPOSURE (host-level) -----------------
    # SSH issue is per-row: it only fires on the actual SSH row so the
    # remediation links to that exposure point. HTTPS issues are host-
    # level because the *protection* applies to the whole host, not the
    # individual port row.
    if row_port == 22 or asset.get("ssh_exposed"):
        risk_score += 15
        issues.append("SSH exposed")
        recommendations.append("Restrict SSH access to trusted networks or VPN")

    if host_context.has_http and not host_context.has_https:
        risk_score += 10
        issues.append("HTTP without HTTPS")
        recommendations.append("Enable HTTPS with a valid TLS certificate")

    if row_port in _SENSITIVE_PORTS:
        risk_score += 12
        issues.append("Sensitive service port exposed")
        recommendations.append("Restrict access to administrative or legacy services")

    # Shadow asset: only fires when an inventory exists AND this IP is not
    # in it. When the inventory is empty, ``known`` is None and we skip
    # the flag entirely (calling every host a shadow asset is just noise).
    if asset.get("known") is False:
        risk_score += 20
        issues.append("Shadow asset detected")
        recommendations.append("Verify ownership and remove unauthorized exposure")

    # "No HTTPS protection" is only meaningful for hosts that serve web
    # traffic (port 80 reachable) and lack 443 entirely. Apply it once at
    # the host level instead of firing it on every non-443 row of every
    # host (which made the flag fire on 100% of rows in the demo data).
    if host_context.has_http and not host_context.has_https:
        risk_score += 8
        issues.append("No HTTPS protection")
        recommendations.append("Enforce TLS for all web services")

    # ---------------- BANNER / FINGERPRINT ----------------------
    banner = asset.get("banner") or ""
    if banner:
        if asset.get("banner_version"):
            risk_score += 5
            issues.append("Service version exposed in banner")
            recommendations.append("Disable or minimize service version disclosure")

        lower = banner.lower()
        if "openssl" in lower and re.search(r"\b1\.0\.", lower):
            risk_score += 20
            issues.append("Outdated OpenSSL 1.0.x detected")
            recommendations.append("Upgrade OpenSSL to a supported (1.1+ / 3.x) version")
        if "openssh" in lower and re.search(r"openssh[_/-]?7\.", lower):
            risk_score += 10
            issues.append("Potentially outdated OpenSSH 7.x")
            recommendations.append("Upgrade OpenSSH to a modern release")
        if "apache" in lower and "2.2" in lower:
            risk_score += 15
            issues.append("Legacy Apache 2.2 detected")
            recommendations.append("Upgrade Apache HTTP Server")

    risk_score = min(risk_score, 100)

    if risk_score < 20:
        severity = "Low"
    elif risk_score < 50:
        severity = "Medium"
    else:
        severity = "High"

    # De-dup while preserving first-seen order so the host detail page
    # shows the most-important driver first.
    asset["risk_score"] = risk_score
    asset["severity"] = severity
    asset["issues"] = list(dict.fromkeys(issues))
    asset["recommendations"] = list(dict.fromkeys(recommendations))
    return asset
