"""Heuristic risk scoring (0–100) for a normalized asset row."""

from __future__ import annotations

import re

_VERSION_RE = re.compile(r"(\d+)(?:\.(\d+))?")
_SENSITIVE_PORTS = {21, 25, 3306, 3389}


def _port_to_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def calculate_risk(asset: dict) -> dict:
    risk_score = 0
    issues: list[str] = []
    recommendations: list[str] = []

    # ---------------- BASE EXPOSURE ----------------
    if asset.get("ssh_exposed"):
        risk_score += 15
        issues.append("SSH exposed")
        recommendations.append("Restrict SSH access to trusted networks or VPN")

    if asset.get("http_exposed") and not asset.get("https_exposed"):
        risk_score += 10
        issues.append("HTTP without HTTPS")
        recommendations.append("Enable HTTPS with a valid TLS certificate")

    port = _port_to_int(asset.get("port"))
    if port in _SENSITIVE_PORTS:
        risk_score += 12
        issues.append("Sensitive service port exposed")
        recommendations.append("Restrict access to administrative or legacy services")

    if not asset.get("known"):
        risk_score += 20
        issues.append("Shadow asset detected")
        recommendations.append("Verify ownership and remove unauthorized exposure")

    if not asset.get("https_exposed"):
        risk_score += 8
        issues.append("No HTTPS protection")
        recommendations.append("Enforce TLS for all web services")

    # ---------------- BANNER / FINGERPRINT ----------------
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
    else:
        risk_score += 5
        issues.append("No banner information available")
        recommendations.append("Enable monitoring or controlled service inspection")

    risk_score = min(risk_score, 100)

    if risk_score < 20:
        severity = "Low"
    elif risk_score < 50:
        severity = "Medium"
    else:
        severity = "High"

    asset["risk_score"] = risk_score
    asset["severity"] = severity
    asset["issues"] = issues
    asset["recommendations"] = sorted(set(recommendations))
    return asset
