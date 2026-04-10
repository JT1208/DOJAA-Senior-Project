import os
import json
import logging
from .collectors import collect_shodan, collect_censys, collect_cves
from .normalizer import normalize_data
from .risk_engine import calculate_risk
from .inventory import load_inventory, compare_with_inventory
from .export_json import save_to_json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_pipeline(output_file="dashboard_data.json", use_api=False):
    """
    Main pipeline:
      1. Collect ALL data from Shodan/Censys (or use cached)
      2. Normalize data
      3. Compare with inventory
      4. Calculate risk scores
      5. Save to JSON for dashboard
    """
    dashboard = {"shodan": [], "censys": [], "cves": []}

    def load_cached_dashboard():
        if not os.path.exists(output_file):
            return {"shodan": [], "censys": [], "cves": []}
        with open(output_file, "r") as f:
            cached = json.load(f)
        return {k: cached.get(k, []) for k in ["shodan", "censys", "cves"]}

    if use_api or not os.path.exists(output_file):
        logger.info("Fetching fresh data from APIs...")
        cached_before_rescan = load_cached_dashboard() if use_api else {"shodan": [], "censys": [], "cves": []}
        try:
            dashboard["shodan"] = collect_shodan()
        except Exception as e:
            logger.error(f"Shodan collection error: {e}")

        try:
            dashboard["censys"] = collect_censys()
        except Exception as e:
            logger.error(f"Censys collection error: {e}")

        try:
            service_records = dashboard["shodan"] + dashboard["censys"]
            dashboard["cves"] = collect_cves(service_records)
        except Exception as e:
            logger.error(f"CVE collection error: {e}")

        # Keep previous data if rescan failed to return any assets.
        if use_api and not dashboard["shodan"] and not dashboard["censys"] and (
            cached_before_rescan["shodan"] or cached_before_rescan["censys"] or cached_before_rescan["cves"]
        ):
            logger.warning("Rescan returned no assets. Keeping cached dashboard data.")
            dashboard = cached_before_rescan
        else:
            save_to_json(dashboard, output_file)
    else:
        logger.info(f"Loading cached data from {output_file}...")
        try:
            dashboard.update(load_cached_dashboard())
        except Exception as e:
            logger.error(f"Failed to load cached data: {e}")

    inventory = load_inventory()

    for key in ["shodan", "censys"]:
        normalized = normalize_data(dashboard[key])
        normalized = compare_with_inventory(normalized, inventory)
        dashboard[key] = [calculate_risk(asset) for asset in normalized]

    logger.info(
        f"Pipeline completed: {len(dashboard['shodan'])} Shodan assets, "
        f"{len(dashboard['censys'])} Censys assets, {len(dashboard['cves'])} CVEs"
    )
    return dashboard