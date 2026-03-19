# dojaa/collectors.py
import requests
from .config import SHODAN_API_KEY, CENSYS_API_TOKEN, ORG_DOMAIN

# --- SHODAN Collector ---
def collect_shodan():
    """
    Collects Shodan host data for the organization domain.
    Returns a list of dicts with consistent keys:
      ip, port, service, banner, provider, ssh_exposed, http_exposed, https_exposed,
      known (optional), risk_score, recommendations
    """
    url = f"https://api.shodan.io/shodan/host/search"
    params = {"key": SHODAN_API_KEY, "query": f"hostname:{ORG_DOMAIN}", "limit": 100}
    
    try:
        resp = requests.get(url, params=params)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        print(f"[Shodan] Error fetching data: {e}")
        return []

    results = []
    for match in data.get("matches", []):
        ip = match.get("ip_str")
        port = match.get("port")
        service_name = match.get("product") or match.get("org") or "Unknown"
        banner = match.get("data") or ""
        ssh_exposed = port == 22
        http_exposed = port == 80
        https_exposed = port == 443

        # Dynamic risk scoring (example logic)
        risk_score = 0
        if http_exposed:
            risk_score += 2
        if https_exposed:
            risk_score += 0
        if ssh_exposed:
            risk_score += 5

        # Basic recommendations
        recommendations = []
        if http_exposed and not https_exposed:
            recommendations.append("Redirect HTTP to HTTPS")
        if ssh_exposed:
            recommendations.append("Ensure SSH uses key-based auth")

        results.append({
            "ip": ip,
            "port": port,
            "service": service_name,
            "banner": banner,
            "provider": match.get("org", ORG_DOMAIN),
            "ssh_exposed": ssh_exposed,
            "http_exposed": http_exposed,
            "https_exposed": https_exposed,
            "known": False,
            "risk_score": risk_score,
            "recommendations": recommendations
        })
    return results


# --- CENSYS Collector ---
def collect_censys():
    """
    Collects Censys host data for the organization domain.
    Returns a list of dicts with consistent keys.
    """
    url = "https://search.censys.io/api/v2/hosts/search"
    headers = {"Accept": "application/json"}
    payload = {
        "q": f"domain:{ORG_DOMAIN}",
        "per_page": 50
    }

    try:
        resp = requests.post(url, headers=headers, auth=(CENSYS_API_TOKEN, ""), json=payload)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        print(f"[Censys] Error fetching data: {e}")
        return []

    results = []
    for hit in data.get("result", {}).get("hits", []):
        ip = hit.get("ip")
        protocols = hit.get("protocols", [])
        services = hit.get("services", [])
        cert_info = hit.get("443", {}).get("tls", {}).get("certificate", {})

        ssh_exposed = any("22/" in p for p in protocols)
        http_exposed = any("80/" in p for p in protocols)
        https_exposed = any("443/" in p for p in protocols)

        # Dynamic risk scoring
        risk_score = 0
        if http_exposed:
            risk_score += 2
        if https_exposed:
            risk_score += 0
        if ssh_exposed:
            risk_score += 5

        # Recommendations
        recommendations = []
        if http_exposed and not https_exposed:
            recommendations.append("Redirect HTTP to HTTPS")
        if ssh_exposed:
            recommendations.append("Ensure SSH uses key-based auth")

        results.append({
            "ip": ip,
            "port": protocols[0].split("/")[0] if protocols else None,
            "service": services[0] if services else "Unknown",
            "banner": str(cert_info) if cert_info else "",
            "provider": hit.get("autonomous_system", {}).get("name", ORG_DOMAIN),
            "ssh_exposed": ssh_exposed,
            "http_exposed": http_exposed,
            "https_exposed": https_exposed,
            "known": False,
            "risk_score": risk_score,
            "recommendations": recommendations
        })
    return results