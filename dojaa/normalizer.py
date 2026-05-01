def normalize_data(raw_data):
    """
    Normalize raw data from Shodan and Censys into a unified schema.
    """

    normalized = []

    for item in raw_data:

        services = item.get("services") or []
        service_name = item.get("service") or (services[0] if services else "Unknown")
        
        is_censys = "resource" in item
        resource = item.get("resource", item)
        c_services = resource.get("services", [])
        first_service = c_services[0] if c_services else {}

        normalized.append({
            "ip": item.get("ip") or resource.get("ip") or "Unknown",
            "port": item.get("port") or (resource.get("services", [{}])[0].get("port") if is_censys else None),
            "service": service_name or (resource.get("services", [{}])[0].get("protocol") if is_censys else None),
            "banner": item.get("banner") or (
                resource.get("services", [{}])[0]
                    .get("endpoints", [{}])[0]
                    .get("http", {})
                    .get("body", "") if is_censys else ""
                ),
            "asn": item.get("asn") or "Unknown",
            "provider": item.get("provider") or "Unknown",
            "ssh_exposed": bool(item.get("ssh_exposed", False)),
            "http_exposed": bool(item.get("http_exposed", False)),
            "https_exposed": bool(item.get("https_exposed", False)),
            "known": False,
            "risk_score": int(item.get("risk_score", 0)),
            "recommendations": item.get("recommendations") or [],
            
            "protocol": first_service.get("protocol") if is_censys else None,
            "transport_protocol": first_service.get("transport_protocol") if is_censys else None,
            "os": (
                resource.get("operating_system", {}).get("product")
                if is_censys else None
            ),
            "key_algorithm": (
                first_service.get("cert", {})
                .get("parsed", {})
                .get("subject_key_info", {})
                .get("key_algorithm", {})
                .get("name")
                if is_censys else None
            )
        })

    return normalized