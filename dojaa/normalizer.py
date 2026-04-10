def normalize_data(raw_data):
    """
    Normalize raw data from Shodan and Censys into a unified schema.
    """

    normalized = []

    for item in raw_data:

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
            "known": False,
            "risk_score": int(item.get("risk_score", 0)),
            "recommendations": item.get("recommendations") or []
        })

    return normalized