# dojaa/inventory.py
import json
from .config import INVENTORY_FILE

# --- Load Inventory ---
def load_inventory():
    """
    Loads the inventory from a JSON file.
    Returns a list of dicts with at least 'ip' key.
    Returns empty list if file is missing or invalid.
    """
    try:
        with open(INVENTORY_FILE, "r") as f:
            data = json.load(f)
            # Ensure each entry has 'ip' key
            normalized = [item for item in data if "ip" in item]
            return normalized
    except FileNotFoundError:
        print(f"[Inventory] File {INVENTORY_FILE} not found, returning empty inventory.")
        return []
    except json.JSONDecodeError as e:
        print(f"[Inventory] Error decoding JSON: {e}")
        return []

# --- Compare Assets with Inventory ---
def compare_with_inventory(normalized_data, inventory=None):
    """
    Marks each asset in normalized_data with 'known': True/False
    based on whether its IP exists in the inventory.
    Accepts optional inventory list; if None, it will load from file.
    """
    if inventory is None:
        inventory = load_inventory()

    inventory_ips = {item["ip"] for item in inventory}

    for asset in normalized_data:
        asset["known"] = asset.get("ip") in inventory_ips

    return normalized_data