"""CISA Known Exploited Vulnerabilities (KEV) catalog client.

Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
Feed:   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Per CISA Binding Operational Directive 22-01, U.S. federal civilian
agencies must remediate entries in this catalog within a fixed window
of their CISA-published due-date. Tagging a matched CVE as a KEV
elevates its priority above its bare CVSS score because real-world
exploitation has been observed.

The catalog is fetched once, cached under
``<cache_dir>/cisa_kev_cache.json``, and refreshed only when older than
``DOJAA_KEV_MAX_AGE_HOURS`` (default 24h). Network failures degrade
gracefully — the previous cache is returned if available, else the
empty set.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

import requests

from ..settings import load_settings

log = logging.getLogger(__name__)

_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _max_age_seconds() -> float:
    try:
        return float(os.environ.get("DOJAA_KEV_MAX_AGE_HOURS", "24")) * 3600
    except ValueError:
        return 24 * 3600


def _cache_path() -> Path:
    return load_settings().cache_dir / "cisa_kev_cache.json"


def _read_cache() -> dict[str, Any] | None:
    path = _cache_path()
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("cisa_kev: cache unreadable (%s)", exc)
        return None


def _write_cache(payload: dict[str, Any]) -> None:
    path = _cache_path()
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(payload))
        os.replace(tmp, path)
    except OSError as exc:
        log.warning("cisa_kev: cache write failed (%s)", exc)


def _fetch_remote() -> dict[str, Any] | None:
    try:
        resp = requests.get(_FEED_URL, timeout=20)
    except requests.RequestException as exc:
        log.warning("cisa_kev: fetch failed (%s)", exc)
        return None
    if resp.status_code != 200:
        log.warning("cisa_kev: HTTP %s", resp.status_code)
        return None
    try:
        return resp.json()
    except ValueError:
        log.warning("cisa_kev: non-JSON response")
        return None


def load_catalog(force_refresh: bool = False) -> dict[str, dict]:
    """Return ``{CVE_ID: entry}`` from the KEV feed.

    Each ``entry`` mirrors the upstream CISA record: ``cveID``,
    ``vendorProject``, ``product``, ``vulnerabilityName``,
    ``dateAdded``, ``shortDescription``, ``requiredAction``, ``dueDate``,
    ``knownRansomwareCampaignUse``, ``notes``.
    """
    cached = _read_cache()
    fresh_enough = (
        cached is not None
        and (time.time() - cached.get("_fetched_at", 0)) < _max_age_seconds()
    )
    if cached and fresh_enough and not force_refresh:
        return cached.get("_by_cve", {})

    remote = _fetch_remote()
    if remote is None:
        if cached:
            log.info("cisa_kev: using stale cache after refresh failure")
            return cached.get("_by_cve", {})
        return {}

    by_cve: dict[str, dict] = {}
    for entry in remote.get("vulnerabilities", []) or []:
        cve_id = (entry.get("cveID") or "").strip()
        if cve_id:
            by_cve[cve_id] = entry

    _write_cache({"_fetched_at": time.time(), "_by_cve": by_cve, "catalogVersion": remote.get("catalogVersion")})
    log.info("cisa_kev: loaded %d known-exploited entries", len(by_cve))
    return by_cve


def is_kev(cve_id: str, catalog: dict[str, dict] | None = None) -> bool:
    """Return True if ``cve_id`` is in the KEV catalog."""
    catalog = catalog if catalog is not None else load_catalog()
    return cve_id in catalog


def kev_metadata(cve_id: str, catalog: dict[str, dict] | None = None) -> dict | None:
    """Return the KEV entry for ``cve_id`` or None."""
    catalog = catalog if catalog is not None else load_catalog()
    return catalog.get(cve_id)
