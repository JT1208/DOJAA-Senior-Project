def calculate_risk(asset):
    risk_score = 0
    issues = []
    recommendations = []

    if asset.get("ssh_exposed"):
        risk_score += 15
        issues.append("SSH exposed")
        recommendations.append("Restrict SSH access")

    if asset.get("http_exposed") and not asset.get("https_exposed"):
        risk_score += 10
        issues.append("HTTP without HTTPS")
        recommendations.append("Enable HTTPS")

    if asset.get("port") in [21, 25, 3306, 3389]:
        risk_score += 12
        issues.append("Sensitive port exposed")
        recommendations.append("Restrict service access")

    if not asset.get("known"):
        risk_score += 20
        issues.append("Shadow asset detected")
        recommendations.append("Verify ownership")

    if not asset.get("https_exposed"):
        risk_score += 8
        issues.append("No HTTPS")

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
    asset["recommendations"] = list(set(recommendations))

    return asset