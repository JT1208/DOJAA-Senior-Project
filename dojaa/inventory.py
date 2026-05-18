"""Internal inventory (known assets) loader and shadow-asset detection.

The inventory is a JSON list of objects. Each entry contributes to the
"known assets" set in one of two ways:

* ``ip``    — a single IPv4 address.
* ``cidr``  — a CIDR block (e.g. ``"129.25.0.0/16"``). All addresses in
              the block are treated as known. Useful when an org owns a
              whole allocation (most universities do).

Anything we discover via recon that isn't covered by either rule is
flagged as a "shadow asset". When the inventory is empty the flag is
disabled entirely — a tool that calls every discovered host a shadow
asset is just noise.

Resolution order for the inventory file (first hit wins):

1. ``DOJAA_INVENTORY_FILE``  — explicit override
2. ``<cache_dir>/internal_inventory.json``
3. ``<repo_root>/data/internal_inventory.json``  — the file checked in
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
from pathlib import Path

from .settings import load_settings

log = logging.getLogger(__name__)


def _candidate_paths() -> list[Path]:
    settings = load_settings()
    paths: list[Path] = []
    override = os.environ.get("DOJAA_INVENTORY_FILE", "").strip()
    if override:
        paths.append(Path(override))
    paths.append(Path(settings.inventory_file))
    paths.append(Path(__file__).resolve().parent.parent / "data" / "internal_inventory.json")
    return paths


def _resolve_inventory_path() -> Path | None:
    for path in _candidate_paths():
        if path.exists() and path.is_file():
            return path
    return None


def load_inventory() -> list[dict]:
    """Return the raw inventory list, or [] if no file is present."""
    path = _resolve_inventory_path()
    if path is None:
        log.info("inventory: no inventory file found in candidate paths")
        return []
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("inventory: cannot read %s (%s)", path, exc)
        return []
    if not isinstance(data, list):
        return []
    items = [item for item in data if isinstance(item, dict) and (item.get("ip") or item.get("cidr"))]
    if items:
        log.info("inventory: loaded %d entries from %s", len(items), path)
    return items


def _parse_index(inventory: list[dict]) -> tuple[set[str], list[ipaddress.IPv4Network], dict[str, dict]]:
    ips: set[str] = set()
    networks: list[ipaddress.IPv4Network] = []
    by_key: dict[str, dict] = {}
    for entry in inventory:
        ip = (entry.get("ip") or "").strip()
        cidr = (entry.get("cidr") or "").strip()
        if ip:
            ips.add(ip)
            by_key.setdefault(ip, entry)
        if cidr:
            try:
                networks.append(ipaddress.ip_network(cidr, strict=False))
                by_key.setdefault(cidr, entry)
            except ValueError:
                log.warning("inventory: invalid CIDR %r — skipping", cidr)
    return ips, networks, by_key


def _is_known(ip: str, ip_set: set[str], networks: list[ipaddress.IPv4Network]) -> bool:
    if ip in ip_set:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in networks)


def compare_with_inventory(
    normalized_data: list[dict], inventory: list[dict] | None = None
) -> list[dict]:
    """Mark each asset as known/shadow against the inventory.

    Matches by direct IP OR by CIDR membership. When the inventory has
    zero entries, ``known`` is left as ``None`` so the risk engine can
    suppress the shadow flag.
    """
    if inventory is None:
        inventory = load_inventory()

    ip_set, networks, _ = _parse_index(inventory)
    has_inventory = bool(ip_set or networks)

    for asset in normalized_data:
        if not has_inventory:
            asset["known"] = None
            asset["shadow_asset"] = None
            continue
        ip = asset.get("ip") or ""
        known = _is_known(ip, ip_set, networks)
        asset["known"] = known
        asset["shadow_asset"] = not known

    return normalized_data
