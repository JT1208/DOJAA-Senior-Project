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


def run_pipeline(output_file="dashboard_data.json", use_api=False):

    dashboard = {
        "shodan": [],
        "censys": [],
        "ssl_tls": []
    }

    # ---------------- LOAD / COLLECT ----------------
    if use_api or not os.path.exists(output_file):
        dashboard["shodan"] = collect_shodan()
        dashboard["censys"] = collect_censys()
        save_to_json(dashboard, output_file)
    else:
        try:
            with open(output_file, "r") as f:
                dashboard = json.load(f)
            dashboard.setdefault("ssl_tls", [])
        except Exception:
            dashboard = {"shodan": [], "censys": [], "ssl_tls": []}

    # ---------------- ENRICHMENT ----------------
    for source in ["shodan", "censys"]:
        for asset in dashboard.get(source, []):

            parsed = parse_banner(asset.get("banner", ""), asset.get("port"))

            asset["banner_service"] = parsed["service"]
            asset["banner_product"] = parsed["product"]
            asset["banner_version"] = parsed["version"]
            asset["banner_summary"] = parsed["summary"]
            asset["banner_risk_hint"] = parsed["risk_hint"]

    # ---------------- RISK ENGINE ----------------
    inventory = load_inventory()

    for source in ["shodan", "censys"]:

        normalized = normalize_data(dashboard.get(source, []))
        normalized = compare_with_inventory(normalized, inventory)

        final = []

        for asset in normalized:
            asset = calculate_risk(asset)

            intel = build_service_intel(asset)
            asset["service_intel"] = intel["service_intel"]
            asset["service_risk_hint"] = intel["service_risk_hint"]

            final.append(asset)

        dashboard[source] = final

    # ---------------- SSL PIPELINE (SAFE + CONTROLLED) ----------------

    hosts = []

    for source in ["shodan", "censys"]:
        for asset in dashboard.get(source, []):
            ip = asset.get("ip")
            port = asset.get("port")

            # ONLY likely HTTPS targets
            if ip and (port == 443 or port == "443"):
                hosts.append(ip)

    hosts = list(set(hosts))

    # 🔥 LIMIT TO PREVENT HANG
    hosts = hosts[:10]

    try:
        dashboard["ssl_tls"] = collect_ssl_data(hosts)
    except Exception as e:
        print("[SSL PIPELINE ERROR]", e)
        dashboard["ssl_tls"] = []

    # ---------------- SAVE ----------------
    try:
        save_to_json(dashboard, output_file)
    except Exception as e:
        print("[PIPELINE SAVE ERROR]", e)

    return dashboard