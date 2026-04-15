# dojaa/collectors.py
import concurrent.futures

import requests
from .config import SHODAN_API_KEY, CENSYS_API_TOKEN, CVE_API_KEY, ORG_DOMAIN

# --- CVE reference URLs: heuristics + HTTP probe + per-reference url_ok flag ---
# Used when building CVE rows so cves.html can show only links that likely work.
# See _annotate_reference_url_ok() and collect_cves() return paths.
_REF_CHECK_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def _reference_url_unreachable_by_heuristic(url: str) -> bool:
    """
    True if the URL should not be offered as a clickable link (known-bad patterns
    without needing a network check).
    """
    u = (url or "").strip().lower()
    if not u.startswith(("http://", "https://")):
        return True
    if u.startswith("javascript:") or u.startswith("data:"):
        return True
    # Retired HP business-support doc hosts (often fail in browsers today).
    if "h20000.www2.hp.com" in u or "h20000.www1.hp.com" in u or "h20000.www.hp.com" in u:
        return True
    gated = (
        "login" in u
        or "signin" in u
        or "/sso/" in u
        or "account." in u
        or "access.redhat.com" in u
        or "support.oracle.com" in u
        or "signon." in u
    )
    if gated:
        return True
    if "localhost" in u or "127.0.0.1" in u or "0.0.0.0" in u:
        return True
    return False


def _reference_url_reachable_http(url: str, timeout: float = 3.5) -> bool:
    """
    Best-effort HTTP probe: True if the URL likely loads in a browser (2xx/3xx).
    Uses HEAD first, then a small GET if HEAD is inconclusive.
    """
    headers = {"User-Agent": _REF_CHECK_UA, "Accept": "*/*"}
    session = requests.Session()

    def _ok_status(code: int) -> bool:
        if code in (429,):
            return True
        return 200 <= code < 400

    for verify in (True, False):
        try:
            r = session.head(url, allow_redirects=True, timeout=timeout, headers=headers, verify=verify)
            if _ok_status(r.status_code):
                return True
            if r.status_code in (401, 403, 405, 501):
                g = session.get(
                    url, allow_redirects=True, timeout=timeout, headers=headers, verify=verify, stream=True
                )
                try:
                    return _ok_status(g.status_code)
                finally:
                    g.close()
            if r.status_code in (404, 410) or r.status_code >= 500:
                return False
            return False
        except requests.exceptions.SSLError:
            continue
        except requests.RequestException:
            if verify is False:
                return False
            continue
    return False


def _reference_url_clickable(url: str) -> bool:
    if _reference_url_unreachable_by_heuristic(url):
        return False
    return _reference_url_reachable_http(url)


def _annotate_reference_url_ok(cve_results):
    """Dedupe URLs, probe in parallel, set url_ok on each NVD reference dict."""
    unique_urls = []
    seen = set()
    for row in cve_results:
        for ref in row.get("references") or []:
            u = (ref.get("url") or "").strip()
            if not u or u in seen:
                continue
            seen.add(u)
            unique_urls.append(u)

    results = {}
    if not unique_urls:
        return

    max_workers = min(8, max(1, len(unique_urls)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {pool.submit(_reference_url_clickable, u): u for u in unique_urls}
        for fut in concurrent.futures.as_completed(future_map):
            u = future_map[fut]
            try:
                results[u] = bool(fut.result())
            except Exception:
                results[u] = False

    for row in cve_results:
        for ref in row.get("references") or []:
            u = (ref.get("url") or "").strip()
            ref["url_ok"] = results.get(u, False)

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


def _cwe_sort_key(entry):
    """Prefer numeric CWE-NNN entries for stable ordering."""
    text = (entry or "").strip()
    if text.upper().startswith("CWE-"):
        rest = text[4:].split(":", 1)[0].strip()
        if rest.isdigit():
            return (0, int(rest), text)
    return (1, 9999, text)


def _extract_cwe_ids(cve):
    """English CWE weakness labels from NVD (e.g. CWE-79 or CWE-79: XSS)."""
    out = []
    for w in cve.get("weaknesses") or []:
        for d in w.get("description", []) or []:
            if d.get("lang") != "en":
                continue
            val = (d.get("value") or "").strip()
            if val and val not in out:
                out.append(val)
    out.sort(key=_cwe_sort_key)
    return out[:12]


def _ref_sort_key(ref):
    tags = " ".join(ref.get("tags") or []).lower()
    url = ref.get("url") or ""
    if "patch" in tags:
        return (0, url)
    if "mitigation" in tags:
        return (1, url)
    if "vendor advisory" in tags:
        return (2, url)
    if "issue tracking" in tags or "third party advisory" in tags:
        return (3, url)
    return (5, url)


def _extract_references(cve, limit=15):
    """NVD reference URLs, ordered toward patches and vendor guidance."""
    raw = []
    for ref in cve.get("references") or []:
        url = (ref.get("url") or "").strip()
        if not url:
            continue
        tags = ref.get("tags") or []
        if not isinstance(tags, list):
            tags = []
        raw.append({"url": url, "tags": tags, "source": (ref.get("source") or "").strip()})
    raw.sort(key=_ref_sort_key)
    return raw[:limit]


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

            # Full English description (dashboard + cves.html); not truncated.
            cve_results.append(
                {
                    "cve_id": cve_id,
                    "service": service,
                    "severity": severity,
                    "cvss_score": score if score is not None else "-",
                    "published": (cve.get("published") or "").split("T")[0],
                    "description": description,
                    "cwe_ids": _extract_cwe_ids(cve),
                    "references": _extract_references(cve),
                }
            )
            seen_cve_ids.add(cve_id)
            if len(cve_results) >= max_total:
                print(f"[CVE] Collected {len(cve_results)} CVEs.")
                # Mark which reference URLs are safe to render as <a href="...">.
                _annotate_reference_url_ok(cve_results)
                return cve_results

    print(f"[CVE] Collected {len(cve_results)} CVEs.")
    _annotate_reference_url_ok(cve_results)
    return cve_results