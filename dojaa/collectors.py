# dojaa/collectors.py
import requests
from .config import SHODAN_API_KEY, CENSYS_API_TOKEN, ORG_DOMAIN

# --- Shodan Collector ---
def collect_shodan():
    """
    Collects Shodan host data for all ports and subdomains of ORG_DOMAIN.
    Returns a list of dicts with keys:
    ip, port, service, banner, provider, ssh_exposed, http_exposed, https_exposed,
    known (optional), risk_score, recommendations
    """
    print("[Shodan] Starting full scan...")
    results = []

    # Common ports to check
    ports = [22, 80, 443, 21, 25, 3306, 3389, 8080, 8443]
    
    # Optional: split by subdomain prefixes if needed
    subdomains = ["", "www", "mail", "vpn", "api"]

    for sd in subdomains:
        domain_query = f"{sd}.{ORG_DOMAIN}" if sd else ORG_DOMAIN
        for port in ports:
            query = f"hostname:{domain_query} port:{port}"
            page = 1
            while True:
                url = "https://api.shodan.io/shodan/host/search"
                params = {"key": SHODAN_API_KEY, "query": query, "page": page}
                try:
                    resp = requests.get(url, params=params)
                    resp.raise_for_status()
                    data = resp.json()
                    matches = data.get("matches", [])
                    if not matches:
                        break
                    for match in matches:
                        ip = match.get("ip_str")
                        port = match.get("port")
                        service_name = match.get("product") or match.get("org") or "Unknown"
                        banner = match.get("data") or ""
                        ssh_exposed = port == 22
                        http_exposed = port == 80
                        https_exposed = port == 443

                        risk_score = 0
                        recommendations = []

                        if ssh_exposed:
                            risk_score += 3
                            recommendations.append("Restrict SSH access")
                        if http_exposed and not https_exposed:
                            risk_score += 2
                            recommendations.append("Redirect HTTP to HTTPS")

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
                    page += 1
                    # Shodan free API only allows 100 results; break to avoid infinite loop
                    if page > 10:
                        break
                except Exception as e:
                    print(f"[Shodan] Error fetching data: {e}")
                    break
    print(f"[Shodan] Collected {len(results)} assets.")
    return results


# --- Censys Collector ---
def collect_censys():
    """
    Collects Censys host data for ORG_DOMAIN with proper pagination.
    Returns a list of dicts matching Shodan format.
    """
    print("[Censys] Starting full scan...")
    url = "https://search.censys.io/api/v2/hosts/search"
    headers = {"Accept": "application/json"}
    payload = {"q": f"domain:{ORG_DOMAIN}", "per_page": 50}

    results = []
    while True:
        try:
            resp = requests.post(url, headers=headers, auth=(CENSYS_API_TOKEN, ""), json=payload)
            resp.raise_for_status()
            data = resp.json()
            hits = data.get("result", {}).get("hits", [])
            if not hits:
                break

            for hit in hits:
                ip = hit.get("ip")
                protocols = hit.get("protocols", [])
                services = hit.get("services", [])
                cert_info = hit.get("443", {}).get("tls", {}).get("certificate", {})

                ssh_exposed = any("22/" in p for p in protocols)
                http_exposed = any("80/" in p for p in protocols)
                https_exposed = any("443/" in p for p in protocols)

                risk_score = 0
                recommendations = []
                if ssh_exposed:
                    risk_score += 3
                    recommendations.append("Restrict SSH access")
                if http_exposed and not https_exposed:
                    risk_score += 2
                    recommendations.append("Redirect HTTP to HTTPS")

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

            # Pagination using links.next
            next_link = data.get("links", {}).get("next")
            if not next_link:
                break
            url = next_link
            payload = {}  # Already included in next_link
        except Exception as e:
            print(f"[Censys] Error fetching data: {e}")
            break

    print(f"[Censys] Collected {len(results)} assets.")
    return results