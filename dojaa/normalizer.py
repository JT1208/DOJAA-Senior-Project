"""Normalize raw Shodan and Censys records into a single host schema."""

from __future__ import annotations

from typing import Any


def _safe_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize_data(raw_data: list[dict]) -> list[dict]:
    """Convert each row into the unified host schema."""
    normalized: list[dict] = []

    for item in raw_data:
        is_censys = "resource" in item
        resource = item.get("resource", item)
        c_services = resource.get("services", []) if is_censys else []
        first_service = c_services[0] if c_services else {}

        port = item.get("port")
        if port is None and is_censys:
            port = first_service.get("port")
        port = _safe_int(port)

        services = item.get("services") or []
        service_name = item.get("service") or (services[0] if services else None)
        if not service_name and is_censys:
            for sw in first_service.get("software", []) or []:
                if sw.get("product"):
                    service_name = sw["product"]
                    break

        banner = item.get("banner")
        if not banner and is_censys:
            banner = (
                first_service.get("endpoints", [{}])[0]
                .get("http", {})
                .get("body", "")
            )

        normalized.append(
            {
                "ip": item.get("ip") or resource.get("ip") or "Unknown",
                "port": port,
                "service": service_name or "Unknown",
                "banner": banner or "",
                "asn": item.get("asn") or "Unknown",
                "provider": item.get("provider") or "Unknown",
                "ssh_exposed": bool(item.get("ssh_exposed", False)),
                "http_exposed": bool(item.get("http_exposed", False)),
                "https_exposed": bool(item.get("https_exposed", False)),
                "known": False,
                "risk_score": int(item.get("risk_score", 0) or 0),
                "recommendations": item.get("recommendations") or [],
                # Censys-only details (None for Shodan rows)
                "protocol": first_service.get("protocol") if is_censys else None,
                "transport_protocol": (
                    first_service.get("transport_protocol") if is_censys else None
                ),
                "os": (
                    resource.get("operating_system", {}).get("product")
                    if is_censys
                    else None
                ),
                "key_algorithm": (
                    first_service.get("cert", {})
                    .get("parsed", {})
                    .get("subject_key_info", {})
                    .get("key_algorithm", {})
                    .get("name")
                    if is_censys
                    else None
                ),
                # banner_* and source are filled in by the pipeline.
                "banner_service": item.get("banner_service"),
                "banner_product": item.get("banner_product"),
                "banner_version": item.get("banner_version"),
                "banner_summary": item.get("banner_summary"),
            }
        )

    return normalized
