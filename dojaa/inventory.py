import json
from .config import INVENTORY_FILE

def load_inventory():
    try:
        with open(INVENTORY_FILE, "r") as f:
            data = json.load(f)
            return [item for item in data if "ip" in item]
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def compare_with_inventory(normalized_data, inventory=None):
    if inventory is None:
        inventory = load_inventory()
    inventory_ips = {item["ip"] for item in inventory}
    for asset in normalized_data:
        asset["known"] = asset.get("ip") in inventory_ips
    return normalized_data