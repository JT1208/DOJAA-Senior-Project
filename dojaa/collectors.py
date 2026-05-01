import requests
from .config import SHODAN_API_KEY, CENSYS_API_TOKEN, CVE_API_KEY, ORG_DOMAIN


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

                    resp = requests.get(url, params=params, timeout=25)
                    if resp.status_code != 200:
                        try:
                            err = resp.json()
                        except Exception:
                            err = resp.text[:300]
                        print(
                            f"[Shodan] HTTP {resp.status_code} (page {page}): {err!r} — "
                            "no credits, invalid key, or rate limit; stopping this query."
                        )
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

    url = "https://search.censys.io/api/v2/hosts/search"
    payload = {"q": f"domain:{ORG_DOMAIN}", "per_page": 50}
    headers = {"Accept": "application/json"}

    try:
        resp = requests.post(
            url,
            headers=headers,
            auth=(CENSYS_API_TOKEN, ""),
            json=payload,
            timeout=30,
        )

        if resp.status_code != 200:
            try:
                err = resp.json()
            except Exception:
                err = resp.text[:300]
            print(f"[Censys] HTTP {resp.status_code}: {err!r}")
            return results

        data = resp.json()
        hits = data.get("result", {}).get("hits", [])

        for hit in hits:
            protocols = hit.get("protocols", [])

            results.append({
                "ip": hit.get("ip"),
                "port": protocols[0].split("/")[0] if protocols else None,
                "service": "Unknown",
                "banner": "",
                "provider": hit.get("autonomous_system", {}).get("name", ORG_DOMAIN),
                "ssh_exposed": any("22/" in p for p in protocols),
                "http_exposed": any("80/" in p for p in protocols),
                "https_exposed": any("443/" in p for p in protocols),
                "known": False,
                "risk_score": 0,
                "recommendations": []
            })

    except Exception as e:
        print("[Censys Error]", e)

    print(f"[Censys] Collected {len(results)} assets")
    return results


# --- NVD CVE lookup (keyword per service from scan rows) ---


def _extract_cvss(metrics: dict) -> tuple:
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(metric_key, [])
        if not metric_list:
            continue
        metric_data = metric_list[0].get("cvssData", {})
        base_score = metric_data.get("baseScore")
        severity = metric_data.get("baseSeverity")
        if base_score is not None:
            return base_score, severity or "UNKNOWN"
    return None, "UNKNOWN"


def _cwe_sort_key(entry: str) -> tuple:
    text = (entry or "").strip()
    if text.upper().startswith("CWE-"):
        rest = text[4:].split(":", 1)[0].strip()
        if rest.isdigit():
            return (0, int(rest), text)
    return (1, 9999, text)


def _extract_cwe_ids(cve: dict) -> list:
    out: list = []
    for w in cve.get("weaknesses") or []:
        for d in w.get("description", []) or []:
            if d.get("lang") != "en":
                continue
            val = (d.get("value") or "").strip()
            if val and val not in out:
                out.append(val)
    out.sort(key=_cwe_sort_key)
    return out[:12]


def _ref_sort_key(ref: dict) -> tuple:
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


def _extract_references(cve: dict, limit: int = 15) -> list:
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


def _reference_url_unreachable_by_heuristic(url: str) -> bool:
    u = (url or "").strip().lower()
    if not u.startswith(("http://", "https://")):
        return True
    if u.startswith("javascript:") or u.startswith("data:"):
        return True
    if "h20000.www2.hp.com" in u or "h20000.www1.hp.com" in u or "h20000.www.hp.com" in u:
        return True
    if (
        "login" in u
        or "signin" in u
        or "/sso/" in u
        or "account." in u
        or "access.redhat.com" in u
        or "support.oracle.com" in u
        or "signon." in u
    ):
        return True
    if "localhost" in u or "127.0.0.1" in u or "0.0.0.0" in u:
        return True
    return False


def _annotate_reference_url_ok(cve_results: list) -> None:
    for row in cve_results:
        for ref in row.get("references") or []:
            u = (ref.get("url") or "").strip()
            ref["url_ok"] = not _reference_url_unreachable_by_heuristic(u)


def collect_cves(service_records, max_cves_per_service=5, max_total=25):
    print("[CVE] Starting NVD CVE lookup...")
    api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"Accept": "application/json"}
    if CVE_API_KEY:
        headers["apiKey"] = CVE_API_KEY

    service_names: set = set()
    for record in service_records:
        service = (record.get("service") or "").strip()
        if service and service.lower() != "unknown":
            service_names.add(service)

    cve_results: list = []
    seen_cve_ids: set = set()

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
                    "description": description,
                    "cwe_ids": _extract_cwe_ids(cve),
                    "references": _extract_references(cve),
                }
            )
            seen_cve_ids.add(cve_id)
            if len(cve_results) >= max_total:
                print(f"[CVE] Collected {len(cve_results)} CVEs.")
                _annotate_reference_url_ok(cve_results)
                return cve_results

    print(f"[CVE] Collected {len(cve_results)} CVEs.")
    _annotate_reference_url_ok(cve_results)
    return cve_results