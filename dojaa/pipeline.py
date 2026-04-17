import os
import json

from .collectors import collect_shodan, collect_censys
from .normalizer import normalize_data
from .inventory import load_inventory, compare_with_inventory
from .risk_engine import calculate_risk
from .export_json import save_to_json

from .enrichment.banner_parser import parse_banner
from .enrichment.service_intel import build_service_intel

from .ssl_tls_collector import collect_ssl_data


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
        print("[CACHE SAVE ERROR]", e)


def run_pipeline(output_file="dashboard_data.json", use_api=False):

    dashboard = {
        "shodan": [],
        "censys": [],
        "ssl_tls": []
    }

    cached = load_cache()

    # ---------------- LOAD OR REFRESH ----------------
    if use_api or not cached:
        dashboard["shodan"] = collect_shodan()
        dashboard["censys"] = collect_censys()
        cache_hit = False
    else:
        dashboard["shodan"] = cached.get("shodan", [])
        dashboard["censys"] = cached.get("censys", [])
        cache_hit = True

    # ---------------- ENRICHMENT ----------------
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

        for asset in normalized:
            asset.update(calculate_risk(asset))
            asset.update(build_service_intel(asset))

        dashboard[source] = normalized

    # ---------------- SSL LOGIC (FIXED) ----------------

    # ALWAYS recompute SSL if:
    # - fresh scan (use_api)
    # - no cache
    # - OR cache mismatch risk (safe default: when not cache hit)

    if use_api or not cache_hit:

        hosts = []

        for a in dashboard.get("shodan", []) + dashboard.get("censys", []):
            if a.get("port") == 443:
                hosts.append(a.get("ip"))

        hosts = list(set(hosts))[:15]

        try:
            dashboard["ssl_tls"] = collect_ssl_data(hosts)
        except Exception as e:
            print("[SSL ERROR]", e)
            dashboard["ssl_tls"] = []

    else:
        # safe cached fallback
        dashboard["ssl_tls"] = cached.get("ssl_tls", [])

    # ---------------- FINAL SAFETY ----------------
    dashboard.setdefault("shodan", [])
    dashboard.setdefault("censys", [])
    dashboard.setdefault("ssl_tls", [])

    # ---------------- SAVE CACHE ----------------
    save_cache(dashboard)

    try:
        save_to_json(dashboard, output_file)
    except Exception as e:
        print("[PIPELINE SAVE ERROR]", e)

    return dashboard