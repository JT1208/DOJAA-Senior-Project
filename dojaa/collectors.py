import requests
from .config import SHODAN_API_KEY, CENSYS_API_TOKEN2, ORG_DOMAIN


def collect_shodan():
    print("[Shodan] Collecting data...")
    results = []

    ports = [22, 80, 443, 21, 25, 3306, 3389]
    subdomains = ["", "www", "mail", "vpn", "api"]

    for sd in subdomains:
        domain = f"{sd}.{ORG_DOMAIN}" if sd else ORG_DOMAIN

        for port in ports:
            query = f"hostname:{domain} port:{port}"
            page = 1

            while page <= 5:
                try:
                    url = "https://api.shodan.io/shodan/host/search"
                    params = {"key": SHODAN_API_KEY, "query": query, "page": page}

                    resp = requests.get(url, params=params)
                    if resp.status_code != 200:
                        break

                    data = resp.json()
                    matches = data.get("matches", [])

                    if not matches:
                        break

                    for match in matches:
                        results.append({
                            "ip": match.get("ip_str"),
                            "port": match.get("port"),
                            "service": match.get("product") or "Unknown",
                            "banner": match.get("data", ""),
                            "provider": match.get("org", ORG_DOMAIN),
                            "ssh_exposed": match.get("port") == 22,
                            "http_exposed": match.get("port") == 80,
                            "https_exposed": match.get("port") == 443,
                            "known": False,
                            "risk_score": 0,
                            "recommendations": []
                        })

                    page += 1

                except Exception as e:
                    print("[Shodan Error]", e)
                    break

    print(f"[Shodan] Collected {len(results)} assets")
    return results


def collect_censys():
    print("Censys] Collecting data...")
    results = []
    
    headers = {
    "Accept": "application/vnd.censys.api.v3.host.v1+json",
    "Authorization": f"Bearer {CENSYS_API_TOKEN2}"
    }
    
    try:
        resp = requests.get(
            "https://api.platform.censys.io/v3/global/asset/host/144.118.67.118",
            headers=headers
        )
        if resp.status_code != 200:
            print(f"[Censys Error], {resp.status_code}")
            return results
        
        data = resp.json()
        results.append(data.get("result", {}))
        
    except Exception as e:
        print("[Censys Error]", e)
        
    print(f"[Censys] Collected {len(results)} assets")
    return results

# def collect_censys():
#     print("[Censys] Collecting data...")
#     results = []

#     url = "https://search.censys.io/api/v2/hosts/search"
#     payload = {"q": f"domain:{ORG_DOMAIN}", "per_page": 50}
#     headers = {"Accept": "application/json"}

#     try:
#         resp = requests.post(
#             url,
#             headers=headers,
#             auth=(CENSYS_API_TOKEN, ""),
#             json=payload
#         )

#         if resp.status_code != 200:
#             return results

#         data = resp.json()
#         hits = data.get("result", {}).get("hits", [])

#         for hit in hits:
#             protocols = hit.get("protocols", [])

#             results.append({
#                 "ip": hit.get("ip"),
#                 "port": protocols[0].split("/")[0] if protocols else None,
#                 "service": "Unknown",
#                 "banner": "",
#                 "provider": hit.get("autonomous_system", {}).get("name", ORG_DOMAIN),
#                 "ssh_exposed": any("22/" in p for p in protocols),
#                 "http_exposed": any("80/" in p for p in protocols),
#                 "https_exposed": any("443/" in p for p in protocols),
#                 "known": False,
#                 "risk_score": 0,
#                 "recommendations": []
#             })

#     except Exception as e:
#         print("[Censys Error]", e)

#     print(f"[Censys] Collected {len(results)} assets")
#     return results