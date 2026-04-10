# dojaa/collectors.py
import requests
from .config import SHODAN_API_KEY, CENSYS_API_TOKEN, CVE_API_KEY, ORG_DOMAIN

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

    stop_scan = False
    for sd in subdomains:
        if stop_scan:
            break
        domain_query = f"{sd}.{ORG_DOMAIN}" if sd else ORG_DOMAIN
        for port in ports:
            if stop_scan:
                break
            query = f"hostname:{domain_query} port:{port}"
            page = 1
            while True:
                url = "https://api.shodan.io/shodan/host/search"
                params = {"key": SHODAN_API_KEY, "query": query, "page": page}
                try:
                    resp = requests.get(url, params=params, timeout=20)
                    if resp.status_code == 401:
                        print("[Shodan] Unauthorized API key (401). Stopping Shodan scan.")
                        stop_scan = True
                        break
                    if resp.status_code == 429:
                        print("[Shodan] Rate-limited by API (429). Stopping Shodan scan.")
                        stop_scan = True
                        break
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
            resp = requests.post(url, headers=headers, auth=(CENSYS_API_TOKEN, ""), json=payload, timeout=20)
            if resp.status_code == 401:
                print("[Censys] Unauthorized API token (401). Stopping Censys scan.")
                break
            if resp.status_code == 429:
                print("[Censys] Rate-limited by API (429). Stopping Censys scan.")
                break
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


def _extract_cvss(metrics):
    for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_list = metrics.get(metric_key, [])
        if not metric_list:
            continue
        metric_data = metric_list[0].get("cvssData", {})
        base_score = metric_data.get("baseScore")
        severity = metric_data.get("baseSeverity")
        if base_score is not None:
            return base_score, severity or "UNKNOWN"
    return None, "UNKNOWN"


def collect_cves(service_records, max_cves_per_service=5, max_total=25):
    """
    Queries NVD CVE API using service names found in scan records.
    Returns CVE rows that can be shown in dashboard tables.
    """
    print("[CVE] Starting NVD CVE lookup...")
    api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"Accept": "application/json"}
    if CVE_API_KEY:
        headers["apiKey"] = CVE_API_KEY

    service_names = set()
    for record in service_records:
        service = (record.get("service") or "").strip()
        if service and service.lower() != "unknown":
            service_names.add(service)

    cve_results = []
    seen_cve_ids = set()

    for service in sorted(service_names):
        params = {"keywordSearch": service, "resultsPerPage": max_cves_per_service}
        try:
            response = requests.get(api_url, headers=headers, params=params, timeout=20)
            response.raise_for_status()
            vulnerabilities = response.json().get("vulnerabilities", [])
        except Exception as e:
            print(f"[CVE] Error fetching data for service '{service}': {e}")
            continue

        for item in vulnerabilities:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id or cve_id in seen_cve_ids:
                continue

            descriptions = cve.get("descriptions", [])
            description = next(
                (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
                descriptions[0].get("value", "") if descriptions else "",
            )
            score, severity = _extract_cvss(cve.get("metrics", {}))

            cve_results.append(
                {
                    "cve_id": cve_id,
                    "service": service,
                    "severity": severity,
                    "cvss_score": score if score is not None else "-",
                    "published": (cve.get("published") or "").split("T")[0],
                    "description": description[:220] + ("..." if len(description) > 220 else ""),
                }
            )
            seen_cve_ids.add(cve_id)
            if len(cve_results) >= max_total:
                print(f"[CVE] Collected {len(cve_results)} CVEs.")
                return cve_results

    print(f"[CVE] Collected {len(cve_results)} CVEs.")
    return cve_results