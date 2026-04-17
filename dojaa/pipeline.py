import os
import json

from .collectors import collect_shodan, collect_censys
from .normalizer import normalize_data
from .inventory import load_inventory, compare_with_inventory
from .risk_engine import calculate_risk
from .export_json import save_to_json

from .enrichment.banner_parser import parse_banner
from .enrichment.service_intel import build_service_intel


def run_pipeline(output_file="dashboard_data.json", use_api=False):

    dashboard = {"shodan": [], "censys": []}

    # ---------------- LOAD / COLLECT ----------------
    if use_api or not os.path.exists(output_file):
        dashboard["shodan"] = collect_shodan()
        dashboard["censys"] = collect_censys()
        save_to_json(dashboard, output_file)
    else:
        try:
            with open(output_file, "r") as f:
                dashboard = json.load(f)
        except Exception:
            dashboard = {"shodan": [], "censys": []}

    # ---------------- BANNER ENRICHMENT ----------------
    for source in ["shodan", "censys"]:
        for asset in dashboard[source]:

            parsed = parse_banner(asset.get("banner", ""), asset.get("port"))

            asset["banner_service"] = parsed["service"]
            asset["banner_product"] = parsed["product"]
            asset["banner_version"] = parsed["version"]
            asset["banner_summary"] = parsed["summary"]
            asset["banner_risk_hint"] = parsed["risk_hint"]

    # ---------------- RISK + INTELLIGENCE ----------------
    inventory = load_inventory()

    for source in ["shodan", "censys"]:

        normalized = normalize_data(dashboard[source])
        normalized = compare_with_inventory(normalized, inventory)

        final = []

        for asset in normalized:

            asset = calculate_risk(asset)

            intel = build_service_intel(asset)
            asset["service_intel"] = intel["service_intel"]
            asset["service_risk_hint"] = intel["service_risk_hint"]

            final.append(asset)

        dashboard[source] = final

    return dashboard