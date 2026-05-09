import os
import json
import re

from .collectors import collect_shodan, collect_censys, collect_cves
from .normalizer import normalize_data
from .inventory import load_inventory, compare_with_inventory
from .risk_engine import calculate_risk
from .export_json import save_to_json

from .enrichment.banner_parser import parse_banner
from .enrichment.service_intel import build_service_intel
from .ssl_tls_collector import collect_ssl_data
from .writeTo_censys_data import save_results


# =========================
# CACHE
# =========================

CACHE_FILE = "dashboard_cache.json"
CENSYS_FILE = "censys_data.json"


def load_cache():
    if not os.path.exists(CACHE_FILE):
        return None
    try:
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return None

def load_censys():
    if not os.path.exists(CENSYS_FILE):
        return None
    try:
        with open(CENSYS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return None


def save_cache(data):
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(data, f)
    except Exception as e:
        print("[CACHE ERROR]", e)


# =========================
# DN PARSER (FIXED)
# =========================

def parse_dn(dn: str):
    if not dn:
        return {"cn": None, "org": None, "country": None, "summary": "-"}

    parts = dict(re.findall(r'(\w+)=([^,]+)', dn))

    cn = parts.get("CN")
    org = parts.get("O")
    country = parts.get("C")

    summary = cn or dn

    if org:
        summary += f" ({org})"
    if country:
        summary += f" [{country}]"

    return {
        "cn": cn,
        "org": org,
        "country": country,
        "summary": summary
    }


def _is_tls_probe_port(port) -> bool:
    """True for 443 whether stored as int (from API) or str (from JSON cache)."""
    if port is None:
        return False
    try:
        return int(port) == 443
    except (TypeError, ValueError):
        return str(port).strip() == "443"


def _ssl_probe_candidate_ips(assets: list) -> list[str]:
    """
    IPs to run collect_ssl_data on (TLS on 443 in fetch_cert).
    Includes rows with port 443 and rows marked https_exposed (Censys/Shodan flags).
    """
    out: list[str] = []
    seen: set[str] = set()
    for a in assets:
        if not a:
            continue
        ip = a.get("ip")
        if not ip:
            continue
        if _is_tls_probe_port(a.get("port")) or a.get("https_exposed"):
            s = str(ip)
            if s not in seen:
                seen.add(s)
                out.append(s)
    return out[:50]


# =========================
# PIPELINE
# =========================

def run_pipeline(output_file="dashboard_data.json", use_api=False):

    dashboard = {
        "shodan": [],
        "censys": [],
        "ssl_tls": []
    }

    cached = load_cache()
    censysData = load_censys()
    pipeline_notices: list[str] = []

    # ---------------- LOAD ----------------
    if use_api or not cached:
        new_shodan = collect_shodan()
        new_censys = collect_censys()
        # Rescan with exhausted Shodan/Censys quota often returns []; keep last good cache
        if use_api and cached:
            if not new_shodan and cached.get("shodan"):
                new_shodan = list(cached["shodan"])
                pipeline_notices.append(
                    "Shodan returned no data (check API key or credits). Using cached Shodan results."
                )
            if not new_censys and censysData.get("censys"):
                new_censys = list(censysData["censys"])
                pipeline_notices.append("Censys returned no data. Using cached Censys results.")
            # if not new_censys and cached.get("censys"):
            #     new_censys = list(cached["censys"])
            #     pipeline_notices.append(
            #         "Censys returned no data. Using cached Censys results."
            #     )
        dashboard["shodan"] = new_shodan
        dashboard["censys"] = new_censys
        try:
            save_results(dashboard["censys"])
        except Exception as e:
            print("[Censys Export] Could not write censys_data.json:", e)
    else:
        dashboard["shodan"] = cached.get("shodan", [])
        dashboard["censys"] = censysData if isinstance(censysData, list) else []
        # dashboard["censys"] = cached.get("censys", [])
        dashboard["ssl_tls"] = cached.get("ssl_tls", [])

    dashboard["_pipeline_notices"] = pipeline_notices

    # ---------------- HOST ENRICHMENT ----------------
    for source in ["shodan", "censys"]:
        for asset in dashboard.get(source, []):

            parsed = parse_banner(asset.get("banner", ""), asset.get("port"))

            asset["banner_service"] = parsed["service"]
            asset["banner_product"] = parsed["product"]
            asset["banner_version"] = parsed["version"]
            asset["banner_summary"] = parsed["summary"]

    # ---------------- RISK ----------------
    inventory = load_inventory()

    for source in ["shodan", "censys"]:
        normalized = normalize_data(dashboard.get(source, []))
        normalized = compare_with_inventory(normalized, inventory)

        enriched = []
        for asset in normalized:
            asset.update(calculate_risk(asset))
            asset.update(build_service_intel(asset))
            enriched.append(asset)

        dashboard[source] = enriched

    # ---------------- CVE (NVD) ----------------
    need_cve_fetch = use_api or (not cached) or (cached is not None and "cves" not in cached)
    if need_cve_fetch:
        try:
            dashboard["cves"] = collect_cves(dashboard["shodan"] + dashboard["censys"])
        except Exception as e:
            print("[CVE] collection error:", e)
            dashboard["cves"] = []
    else:
        dashboard["cves"] = cached.get("cves", [])

    # ---------------- SSL COLLECTION ----------------

    if use_api or not cached or "ssl_tls" not in cached:

        combined_assets = dashboard.get("shodan", []) + dashboard.get("censys", [])
        hosts = _ssl_probe_candidate_ips(combined_assets)
        fresh_ssl = collect_ssl_data(hosts) if hosts else []
        if use_api and cached and not fresh_ssl and cached.get("ssl_tls"):
            dashboard["ssl_tls"] = list(cached["ssl_tls"])
            pipeline_notices.append(
                "SSL/TLS probe returned no rows (no reachable HTTPS hosts). Using cached SSL/TLS results."
            )
        else:
            dashboard["ssl_tls"] = fresh_ssl

    else:
        dashboard["ssl_tls"] = cached.get("ssl_tls", [])

    # =========================
    # SSL NORMALIZATION (FIXED)
    # =========================

    for cert in dashboard.get("ssl_tls", []):

        issuer_raw = cert.get("issuer", "")
        subject_raw = cert.get("subject", "")

        issuer = parse_dn(issuer_raw)
        subject = parse_dn(subject_raw)

        # CLEAN STRUCTURE (NO MIXING RAW + PARSED)
        cert["issuer_name"] = issuer["summary"]
        cert["subject_name"] = subject["summary"]

        cert["issuer_cn"] = issuer["cn"]
        cert["subject_cn"] = subject["cn"]

        # SAN normalization
        san = cert.get("san") or cert.get("sans") or []
        if isinstance(san, str):
            san = [san]
        cert["san_clean"] = san

        # TRUST MODEL (REALISTIC)
        issuer_l = issuer_raw.lower()

        if "let's encrypt" in issuer_l:
            cert["trust"] = "Public CA"
        elif "digicert" in issuer_l:
            cert["trust"] = "Public CA"
        elif "amazon" in issuer_l:
            cert["trust"] = "Cloud CA"
        elif "incommon" in issuer_l:
            cert["trust"] = "Enterprise CA"
        elif "traefik" in issuer_l or issuer_raw == "CN=TRAEFIK DEFAULT CERT":
            cert["trust"] = "Dev / Default Cert"
        elif issuer_raw in ["", "-", None]:
            cert["trust"] = "Broken / Missing"
        else:
            cert["trust"] = "Unknown CA"

    # ---------------- SAVE ----------------
    _notices = dashboard.pop("_pipeline_notices", [])

    save_cache(dashboard)

    try:
        save_to_json(dashboard, output_file)
    except Exception as e:
        print("[EXPORT ERROR]", e)

    dashboard["_pipeline_notices"] = _notices
    return dashboard