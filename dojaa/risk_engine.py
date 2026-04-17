def calculate_risk(asset):
    risk_score = 0
    issues = []
    recommendations = []

    # ---------------- BASE EXPOSURE RISKS ----------------

    if asset.get("ssh_exposed"):
        risk_score += 15
        issues.append("SSH exposed")
        recommendations.append("Restrict SSH access to trusted networks or VPN")

    if asset.get("http_exposed") and not asset.get("https_exposed"):
        risk_score += 10
        issues.append("HTTP without HTTPS")
        recommendations.append("Enable HTTPS with valid TLS certificate")

    if asset.get("port") in [21, 25, 3306, 3389]:
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

    # ---------------- BANNER / FINGERPRINT RISKS ----------------

    banner = asset.get("banner") or ""

    if banner:
        # version disclosure risk
        if asset.get("banner_version"):
            risk_score += 5
            issues.append("Service version exposed in banner")
            recommendations.append("Disable or minimize service version disclosure")

        # generic insecure indicators
        banner_lower = banner.lower()

        if "openssl" in banner_lower and "1.0" in banner_lower:
            risk_score += 20
            issues.append("Outdated OpenSSL version detected")
            recommendations.append("Upgrade OpenSSL to a supported version")

        if "ssh" in banner_lower and "7." in banner_lower:
            risk_score += 10
            issues.append("Potentially outdated SSH version")
            recommendations.append("Upgrade OpenSSH to a modern release")

        if "apache" in banner_lower and "2.2" in banner_lower:
            risk_score += 15
            issues.append("Legacy Apache version detected")
            recommendations.append("Upgrade Apache HTTP Server")

    else:
        risk_score += 5
        issues.append("No banner information available")
        recommendations.append("Enable monitoring or controlled service inspection")

    # ---------------- FINAL SCORING ----------------

    risk_score = min(risk_score, 100)

    if risk_score < 20:
        severity = "Low"
    elif risk_score < 50:
        severity = "Medium"
    else:
        severity = "High"

    # ---------------- OUTPUT STRUCTURE ----------------

    asset["risk_score"] = risk_score
    asset["severity"] = severity
    asset["issues"] = issues
    asset["recommendations"] = list(set(recommendations))

    return asset