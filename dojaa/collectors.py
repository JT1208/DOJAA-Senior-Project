"""External recon API collectors: Shodan, Censys v2, NVD.

Every collector returns ``(rows, error_message)`` so the pipeline can surface
the failure reason as a user-visible flash notice. ``error_message`` is None
on success or when there was nothing to do; a non-empty string means "show
this to the user."
"""

from __future__ import annotations

import logging
from typing import Iterable

import requests

from .settings import load_settings

log = logging.getLogger(__name__)


def _shodan_status_hint(code: int, body: str) -> str:
    if code == 401:
        return "invalid API key"
    if code == 402:
        return "Shodan account has no scan credits left"
    if code == 403:
        return "API key lacks the required permissions"
    if code == 429:
        return "rate limit exceeded — wait and retry"
    snippet = (body or "").strip().replace("\n", " ")[:120]
    return f"HTTP {code} — {snippet}" if snippet else f"HTTP {code}"


# ---------------- SHODAN ----------------

_SHODAN_PORTS = (22, 80, 443, 21, 25, 3306, 3389)
_SHODAN_SUBDOMAINS = ("", "www", "mail", "vpn", "api")
_SHODAN_URL = "https://api.shodan.io/shodan/host/search"


def collect_shodan() -> tuple[list[dict], str | None]:
    settings = load_settings()
    if not settings.has_shodan:
        log.info("shodan: SHODAN_API_KEY not set, skipping")
        return [], "SHODAN_API_KEY is not set in your environment."

    results: list[dict] = []
    log.info("shodan: collecting for %s", settings.org_domain)
    first_error: str | None = None

    for sd in _SHODAN_SUBDOMAINS:
        domain = f"{sd}.{settings.org_domain}" if sd else settings.org_domain
        for port in _SHODAN_PORTS:
            query = f"hostname:{domain} port:{port}"
            for page in range(1, 6):
                try:
                    resp = requests.get(
                        _SHODAN_URL,
                        params={"key": settings.shodan_api_key, "query": query, "page": page},
                        timeout=25,
                    )
                except requests.RequestException as exc:
                    log.warning("shodan: request failed for %s page %d: %s", query, page, exc)
                    if first_error is None:
                        first_error = f"Shodan request failed: {exc}"
                    break

                if resp.status_code != 200:
                    hint = _shodan_status_hint(resp.status_code, resp.text)
                    log.warning("shodan: %s for %s page %d", hint, query, page)
                    if first_error is None:
                        first_error = f"Shodan: {hint}"
                    break

                try:
                    data = resp.json()
                except ValueError:
                    log.warning("shodan: non-JSON response for %s page %d", query, page)
                    break

                matches = data.get("matches") or []
                if not matches:
                    break

                for m in matches:
                    p = m.get("port")
                    results.append(
                        {
                            "ip": m.get("ip_str"),
                            "port": p,
                            "service": m.get("product") or "Unknown",
                            "banner": m.get("data", ""),
                            "provider": m.get("org", settings.org_domain),
                            "ssh_exposed": p == 22,
                            "http_exposed": p == 80,
                            "https_exposed": p == 443,
                            "known": False,
                            "risk_score": 0,
                            "recommendations": [],
                            "source": "shodan",
                        }
                    )

    log.info("shodan: collected %d assets", len(results))
    # If we collected nothing AND saw an error, propagate it. If we collected
    # at least some rows, treat the partial errors as non-blocking.
    return results, (first_error if not results else None)


# ---------------- CENSYS v2 ----------------

_CENSYS_URL = "https://search.censys.io/api/v2/hosts/search"


def _censys_status_hint(code: int, body: str) -> str:
    if code == 401:
        return "token rejected — check CENSYS_API_TOKEN"
    if code == 403:
        return "token lacks permission for the hosts API"
    if code == 429:
        return "rate limit exceeded — wait and retry"
    snippet = (body or "").strip().replace("\n", " ")[:120]
    return f"HTTP {code} — {snippet}" if snippet else f"HTTP {code}"


def collect_censys() -> tuple[list[dict], str | None]:
    settings = load_settings()
    if not settings.has_censys:
        log.info("censys: CENSYS_API_TOKEN not set, skipping")
        return [], "CENSYS_API_TOKEN is not set in your environment."

    log.info("censys: collecting for %s", settings.org_domain)
    # Censys v2 accepts either a Personal Access Token (alone) or an API ID
    # plus API Secret as HTTP Basic auth. If CENSYS_API_SECRET is set we use
    # the two-part form; otherwise we pass the token as username with empty
    # password (works for PATs).
    auth = (settings.censys_api_token, settings.censys_api_secret)
    try:
        resp = requests.post(
            _CENSYS_URL,
            auth=auth,
            headers={"Accept": "application/json"},
            json={"q": f"domain:{settings.org_domain}", "per_page": 50},
            timeout=30,
        )
    except requests.RequestException as exc:
        log.warning("censys: request failed: %s", exc)
        return [], f"Censys request failed: {exc}"

    if resp.status_code != 200:
        hint = _censys_status_hint(resp.status_code, resp.text)
        log.warning("censys: %s", hint)
        return [], f"Censys: {hint}"

    try:
        data = resp.json()
    except ValueError:
        log.warning("censys: non-JSON response")
        return [], "Censys returned a non-JSON response."

    hits = data.get("result", {}).get("hits", []) or []
    out: list[dict] = []
    for hit in hits:
        protocols = hit.get("protocols") or []
        out.append(
            {
                "ip": hit.get("ip"),
                "port": protocols[0].split("/")[0] if protocols else None,
                "service": "Unknown",
                "banner": "",
                "provider": hit.get("autonomous_system", {}).get("name", settings.org_domain),
                "ssh_exposed": any("22/" in p for p in protocols),
                "http_exposed": any("80/" in p for p in protocols),
                "https_exposed": any("443/" in p for p in protocols),
                "known": False,
                "risk_score": 0,
                "recommendations": [],
                "source": "censys",
            }
        )

    log.info("censys: collected %d assets", len(out))
    return out, None


# ---------------- NVD CVE ----------------

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _extract_cvss(metrics: dict) -> tuple[float | None, str, str | None]:
    """Return ``(base_score, severity, vector)`` preferring CVSS v3.1 → v3.0 → v2."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        lst = metrics.get(key) or []
        if not lst:
            continue
        cvss = lst[0].get("cvssData") or {}
        score = cvss.get("baseScore")
        severity = cvss.get("baseSeverity") or "UNKNOWN"
        vector = cvss.get("vectorString") or None
        if score is not None:
            return score, severity, vector
    return None, "UNKNOWN", None


def _cwe_sort_key(entry: str) -> tuple:
    text = (entry or "").strip()
    if text.upper().startswith("CWE-"):
        rest = text[4:].split(":", 1)[0].strip()
        if rest.isdigit():
            return (0, int(rest), text)
    return (1, 9999, text)


def _extract_cwe_ids(cve: dict) -> list[str]:
    out: list[str] = []
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


def _extract_references(cve: dict, limit: int = 15) -> list[dict]:
    raw: list[dict] = []
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


def _is_unreachable_url(url: str) -> bool:
    u = (url or "").strip().lower()
    if not u.startswith(("http://", "https://")):
        return True
    gated_substrings = (
        "/login", "/signin", "/sso/", "account.", "access.redhat.com",
        "support.oracle.com", "signon.", "h20000.www2.hp.com",
        "h20000.www1.hp.com", "h20000.www.hp.com",
    )
    if any(s in u for s in gated_substrings):
        return True
    if any(host in u for host in ("localhost", "127.0.0.1", "0.0.0.0")):
        return True
    return False


def _annotate_url_reachability(rows: Iterable[dict]) -> None:
    for row in rows:
        for ref in row.get("references") or []:
            ref["url_ok"] = not _is_unreachable_url(ref.get("url", ""))


def _nvd_query(headers: dict, params: dict) -> list[dict]:
    """Single NVD call; returns the vulnerabilities array or []."""
    try:
        resp = requests.get(_NVD_URL, headers=headers, params=params, timeout=25)
        resp.raise_for_status()
        return resp.json().get("vulnerabilities", []) or []
    except (requests.RequestException, ValueError) as exc:
        log.warning("nvd: lookup failed for %s: %s", params, exc)
        return []


def _row_query_key(row: dict) -> tuple[str, dict]:
    """Decide the most precise NVD query for a row.

    Preference order: CPE name (from banner_parser) → vendor+product+version
    keyword → service name. Returns (key_for_dedup, http_params).
    """
    cpe = (row.get("cpe") or "").strip()
    if cpe and cpe.startswith("cpe:2.3:"):
        return cpe, {"cpeName": cpe}

    vendor  = (row.get("banner_vendor") or "").strip()
    product = (row.get("banner_product") or row.get("service") or "").strip()
    version = (row.get("banner_version") or "").strip()
    parts = [p for p in (vendor, product, version) if p and p.lower() != "unknown"]
    if parts:
        kw = " ".join(parts).replace("_", " ")
        return f"kw:{kw}", {"keywordSearch": kw, "keywordExactMatch": ""}
    return "", {}


def collect_cves(service_records: list[dict]) -> list[dict]:
    """Collect CVEs from NVD for each unique service signature.

    Uses CPE-based queries (much more precise than keyword search) when
    the banner parser produced a CPE. Falls back to a vendor+product+
    version keyword. Each row is tagged with its CVSS v3.1 vector,
    CISA-KEV membership (if any), and EPSS exploitation probability.
    """
    settings = load_settings()
    api_key = settings.nvd_api_key
    per_query = settings.cve_max_per_service
    max_total = settings.cve_max_total

    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key

    # Build a unique set of (cpe-or-keyword) queries.
    queries: dict[str, dict] = {}
    label_for_query: dict[str, str] = {}
    for r in service_records:
        key, params = _row_query_key(r)
        if not key or key in queries:
            continue
        queries[key] = params
        # Label used as the human-readable "service" field on each CVE.
        if r.get("banner_product") and r.get("banner_version"):
            label_for_query[key] = f"{r['banner_product']} {r['banner_version']}".replace("_", " ").title()
        else:
            label_for_query[key] = (r.get("service") or "Unknown")

    log.info("nvd: built %d unique queries from %d service rows", len(queries), len(service_records))

    out: list[dict] = []
    seen: set[str] = set()
    for query_key, params in queries.items():
        params = {**params, "resultsPerPage": per_query}
        for item in _nvd_query(headers, params):
            cve = item.get("cve") or {}
            cve_id = cve.get("id")
            if not cve_id or cve_id in seen:
                continue
            seen.add(cve_id)

            descriptions = cve.get("descriptions", []) or []
            description = next(
                (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
                descriptions[0].get("value", "") if descriptions else "",
            )
            score, severity, vector = _extract_cvss(cve.get("metrics") or {})
            out.append(
                {
                    "cve_id": cve_id,
                    "service": label_for_query.get(query_key, "Unknown"),
                    "severity": severity,
                    "cvss_score": score if score is not None else "-",
                    "cvss_vector": vector,
                    "published": (cve.get("published") or "").split("T")[0],
                    "description": description,
                    "cwe_ids": _extract_cwe_ids(cve),
                    "references": _extract_references(cve),
                }
            )
            if len(out) >= max_total:
                _annotate_url_reachability(out)
                _annotate_kev_and_epss(out)
                log.info("nvd: collected %d CVEs (cap reached)", len(out))
                return out

    _annotate_url_reachability(out)
    _annotate_kev_and_epss(out)
    log.info("nvd: collected %d CVEs", len(out))
    return out


def _annotate_kev_and_epss(rows: list[dict]) -> None:
    """Tag each CVE row with CISA KEV membership and EPSS probability."""
    if not rows:
        return
    cve_ids = [r["cve_id"] for r in rows if r.get("cve_id")]

    try:
        from .scoring.cisa_kev import load_catalog as _kev_catalog
        kev_catalog = _kev_catalog()
    except Exception as exc:  # noqa: BLE001 — KEV is best-effort
        log.warning("nvd: KEV enrichment skipped (%s)", exc)
        kev_catalog = {}

    try:
        from .scoring.epss import lookup as _epss_lookup
        epss = _epss_lookup(cve_ids)
    except Exception as exc:  # noqa: BLE001 — EPSS is best-effort
        log.warning("nvd: EPSS enrichment skipped (%s)", exc)
        epss = {}

    for r in rows:
        cid = r.get("cve_id")
        kev_entry = kev_catalog.get(cid) if cid else None
        r["is_kev"] = bool(kev_entry)
        if kev_entry:
            r["kev_due_date"] = kev_entry.get("dueDate")
            r["kev_required_action"] = kev_entry.get("requiredAction")
            r["kev_ransomware_use"] = kev_entry.get("knownRansomwareCampaignUse")
        epss_entry = epss.get(cid) if cid else None
        if epss_entry:
            r["epss_score"] = epss_entry.get("epss")
            r["epss_percentile"] = epss_entry.get("percentile")
            r["epss_date"] = epss_entry.get("date")
