"""FIRST.org Exploit Prediction Scoring System (EPSS) client.

Source: https://www.first.org/epss/
API:    https://api.first.org/data/v1/epss

EPSS provides, for each CVE, a probability (0–1) that the CVE will be
exploited in the wild in the next 30 days, plus a percentile rank
against all other CVEs. It complements CVSS (which measures severity
*if* exploited) with the *likelihood* dimension that NIST 800-30 risk
assessments require.

Up to 100 CVEs may be batched per request. The client caches results
under ``<cache_dir>/epss_cache.json`` with a configurable TTL.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Iterable

import requests

from ..settings import load_settings

log = logging.getLogger(__name__)

_API_URL = "https://api.first.org/data/v1/epss"
_BATCH = 100


def _max_age_seconds() -> float:
    try:
        return float(os.environ.get("DOJAA_EPSS_MAX_AGE_HOURS", "24")) * 3600
    except ValueError:
        return 24 * 3600


def _cache_path() -> Path:
    return load_settings().cache_dir / "epss_cache.json"


def _read_cache() -> dict[str, Any]:
    path = _cache_path()
    if not path.exists():
        return {"_fetched_at": 0, "by_cve": {}}
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {"_fetched_at": 0, "by_cve": {}}


def _write_cache(payload: dict[str, Any]) -> None:
    path = _cache_path()
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(payload))
        os.replace(tmp, path)
    except OSError as exc:
        log.warning("epss: cache write failed (%s)", exc)


def _fetch_batch(cve_ids: list[str]) -> dict[str, dict]:
    if not cve_ids:
        return {}
    try:
        resp = requests.get(_API_URL, params={"cve": ",".join(cve_ids)}, timeout=20)
    except requests.RequestException as exc:
        log.warning("epss: batch fetch failed (%s)", exc)
        return {}
    if resp.status_code != 200:
        log.warning("epss: HTTP %s", resp.status_code)
        return {}
    try:
        data = resp.json()
    except ValueError:
        return {}

    out: dict[str, dict] = {}
    for entry in data.get("data", []) or []:
        cve_id = entry.get("cve")
        if not cve_id:
            continue
        try:
            epss = float(entry.get("epss", 0) or 0)
            percentile = float(entry.get("percentile", 0) or 0)
        except (TypeError, ValueError):
            continue
        out[cve_id] = {"epss": epss, "percentile": percentile, "date": entry.get("date")}
    return out


def lookup(cve_ids: Iterable[str]) -> dict[str, dict]:
    """Return ``{CVE_ID: {"epss":..., "percentile":..., "date":...}}``.

    Missing entries (CVE not found, or network failure) are simply
    absent from the return value — callers should treat absence as
    "unknown EPSS" rather than zero.
    """
    ids = sorted({c for c in (cve_ids or []) if c})
    if not ids:
        return {}

    cache = _read_cache()
    by_cve: dict[str, dict] = dict(cache.get("by_cve", {}))
    age = time.time() - cache.get("_fetched_at", 0)
    if age < _max_age_seconds():
        if all(cve in by_cve for cve in ids):
            return {cve: by_cve[cve] for cve in ids if cve in by_cve}

    # Refresh missing or stale CVEs.
    missing = [c for c in ids if c not in by_cve]
    fetched = 0
    for i in range(0, len(missing), _BATCH):
        chunk = missing[i:i + _BATCH]
        batch_result = _fetch_batch(chunk)
        by_cve.update(batch_result)
        fetched += len(batch_result)

    cache["_fetched_at"] = time.time()
    cache["by_cve"] = by_cve
    _write_cache(cache)
    log.info("epss: fetched %d new entries (%d total cached)", fetched, len(by_cve))
    return {cve: by_cve[cve] for cve in ids if cve in by_cve}
