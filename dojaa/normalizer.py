# dojaa/normalizer.py
def normalize_data(raw_data):
    """
    Normalize raw asset data from various sources (Shodan, Censys, etc.)
    into a consistent format for processing and visualization.

    Each asset will have:
      - ip, port, service, banner, asn, provider
      - ssh_exposed, http_exposed, https_exposed
      - known (boolean)
      - risk_score (int)
      - recommendations (list)
    """
    normalized = []

    for item in raw_data:
        # Ensure services is a list if present
        services = item.get("services") or []
        service_name = item.get("service") or (services[0] if services else "Unknown")

        normalized.append({
            "ip": item.get("ip") or "Unknown",
            "port": item.get("port"),
            "service": service_name,
            "banner": item.get("banner") or "",
            "asn": item.get("asn") or "Unknown",
            "provider": item.get("provider") or "Unknown",
            "ssh_exposed": bool(item.get("ssh_exposed", False)),
            "http_exposed": bool(item.get("http_exposed", False)),
            "https_exposed": bool(item.get("https_exposed", False)),
            "known": False,  # Will be set by inventory comparison
            "risk_score": int(item.get("risk_score", 0)),
            "recommendations": item.get("recommendations") or []
        })

    return normalized