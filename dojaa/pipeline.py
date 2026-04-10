import os
import json

from .collectors import collect_shodan, collect_censys
from .normalizer import normalize_data
from .inventory import load_inventory, compare_with_inventory
from .risk_engine import calculate_risk
from .export_json import save_to_json


def run_pipeline(output_file="dashboard_data.json", use_api=False):
    """
    Full DOJAA pipeline:
    collect → normalize → inventory match → risk scoring → export
    """

    dashboard = {"shodan": [], "censys": []}

    # --- COLLECTION ---
    if use_api or not os.path.exists(output_file):
        print("[Pipeline] Collecting fresh data...")

        dashboard["shodan"] = collect_shodan()
        dashboard["censys"] = collect_censys()

        save_to_json(dashboard, output_file)

    else:
        print("[Pipeline] Loading cached data...")

        try:
            with open(output_file, "r") as f:
                dashboard = json.load(f)
        except Exception as e:
            print("[Pipeline Error]", e)

    # --- PROCESSING ---
    inventory = load_inventory()

    for source in ["shodan", "censys"]:
        normalized = normalize_data(dashboard[source])
        normalized = compare_with_inventory(normalized, inventory)
        dashboard[source] = [calculate_risk(a) for a in normalized]

    print("[Pipeline] Completed successfully")

    return dashboard