def calculate_risk(asset):
    risk_score = 0
    recommendations = []

    if asset.get("ssh_exposed"):
        risk_score += 3
        recommendations.append("Restrict SSH access")
    if asset.get("http_exposed"):
        risk_score += 2
        recommendations.append("Redirect HTTP to HTTPS")
    if asset.get("shadow_asset"):
        risk_score += 5
        recommendations.append("Investigate unauthorized asset")

    asset["risk_score"] = risk_score
    asset["recommendations"] = recommendations
    return asset