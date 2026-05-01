import requests
import json
import time
from .config import SHODAN_API_KEY, CENSYS_API_TOKEN4, ORG_DOMAIN


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
    print("[Censys] Collecting data...")
    results = []

    host_headers = {
        "Accept": "application/vnd.censys.api.v3.host.v1+json",
        "Authorization": f"Bearer {CENSYS_API_TOKEN4}"
    }

    tmp_ip = []
    
    with open("ip_list.json", "r") as f:
        known_ips = json.load(f)

    for ip in tmp_ip:
        try:
            host_resp = requests.get(
                f"https://api.platform.censys.io/v3/global/asset/host/{ip}",
                headers=host_headers
            )
            if host_resp.status_code == 429:
                print(f"[Censys] Rate limited on {ip}, waiting 10 seconds...")
                time.sleep(10)
                # Retry once after waiting
                host_resp = requests.get(
                    f"https://api.platform.censys.io/v3/global/asset/host/{ip}",
                    headers=host_headers
                )
            if host_resp.status_code == 403:
                print("[Censys] Credit limit or auth failure")
                return results
            if host_resp.status_code != 200:
                print(f"[Censys Error] Host {ip} - {host_resp.status_code}")
                continue

            results.append(host_resp.json().get("result", {}))

        except Exception as e:
            print(f"[Censys Error] Host fetch {ip} -", e)

    print(f"[Censys] Collected {len(results)} assets")
    return results
