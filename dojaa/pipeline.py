import os
import json
import re

from .collectors import collect_shodan, collect_censys
from .normalizer import normalize_data
from .inventory import load_inventory, compare_with_inventory
from .risk_engine import calculate_risk
from .export_json import save_to_json

from .enrichment.banner_parser import parse_banner
from .enrichment.service_intel import build_service_intel
from .ssl_tls_collector import collect_ssl_data


# =========================
# CACHE
# =========================

CACHE_FILE = "dashboard_cache.json"


def load_cache():
    if not os.path.exists(CACHE_FILE):
        return None
    try:
        with open(CACHE_FILE, "r") as f:
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

    # ---------------- LOAD ----------------
    if use_api or not cached:
        dashboard["shodan"] = collect_shodan()
        dashboard["censys"] = collect_censys()
    else:
        dashboard["shodan"] = cached.get("shodan", [])
        dashboard["censys"] = cached.get("censys", [])
        dashboard["ssl_tls"] = cached.get("ssl_tls", [])

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

    # ---------------- SSL COLLECTION ----------------

    if use_api or not cached or "ssl_tls" not in cached:

        hosts = []

        for a in dashboard.get("shodan", []) + dashboard.get("censys", []):
            if a.get("port") == 443:
                hosts.append(a.get("ip"))

        hosts = list(set(hosts))[:50]
        dashboard["ssl_tls"] = collect_ssl_data(hosts)

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
    save_cache(dashboard)

    try:
        save_to_json(dashboard, output_file)
    except Exception as e:
        print("[EXPORT ERROR]", e)

    return dashboard