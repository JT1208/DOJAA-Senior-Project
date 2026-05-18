"""Internal inventory (known assets) loader and shadow-asset detection."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from .settings import load_settings

log = logging.getLogger(__name__)


def load_inventory() -> list[dict]:
    """Return the list of known assets, or [] if no inventory is present."""
    path = Path(load_settings().inventory_file)
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("inventory: cannot read %s (%s)", path, exc)
        return []
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict) and "ip" in item]


def compare_with_inventory(
    normalized_data: list[dict], inventory: list[dict] | None = None
) -> list[dict]:
    """Mark each asset as known/shadow based on the inventory IP list."""
    if inventory is None:
        inventory = load_inventory()
    inventory_ips = {item["ip"] for item in inventory if item.get("ip")}

    for asset in normalized_data:
        asset["known"] = asset.get("ip") in inventory_ips
        asset["shadow_asset"] = not asset["known"]

    return normalized_data
