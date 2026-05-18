"""Orchestrates the recon pipeline: collect → enrich → score → cache.

The pipeline degrades gracefully when API keys are missing or quotas are
exhausted: each collector returns an empty list rather than raising, and the
last good cache is used as a fallback. A list of human-readable notices is
attached to the returned payload as ``_pipeline_notices`` so the UI can
explain what happened.

Scoring is delegated to :mod:`dojaa.scoring.engine`, which evaluates each
host against the formal findings catalog (CWE / CVSS v3.1 / NIST 800-53 /
MITRE ATT&CK / CISA KEV / EPSS) rather than ad-hoc point values.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict

from .collectors import collect_censys, collect_cves, collect_shodan
from .enrichment.banner_parser import parse_banner
from .enrichment.service_intel import build_service_intel
from .inventory import compare_with_inventory, load_inventory
from .normalizer import normalize_data
from .scoring.engine import attach_per_row, build_snapshots, score_snapshot
from .services.cache import read_freshness, read_json, write_json
from .settings import load_settings
from .ssl_tls_collector import collect_ssl_data

log = logging.getLogger(__name__)


_DN_FIELD_RE = re.compile(r"(\w+)=([^,]+)")


def _parse_dn(dn: str) -> dict[str, str | None]:
    if not dn:
        return {"cn": None, "org": None, "country": None, "summary": "-"}
    parts = dict(_DN_FIELD_RE.findall(dn))
    cn, org, country = parts.get("CN"), parts.get("O"), parts.get("C")
    summary = cn or dn
    if org:
        summary += f" ({org})"
    if country:
        summary += f" [{country}]"
    return {"cn": cn, "org": org, "country": country, "summary": summary}


def _classify_trust(issuer_raw: str) -> str:
    if not issuer_raw or issuer_raw == "-":
        return "Broken / Missing"
    issuer_l = issuer_raw.lower()
    if "let's encrypt" in issuer_l or "digicert" in issuer_l or "sectigo" in issuer_l:
        return "Public CA"
    if "amazon" in issuer_l or "cloudflare" in issuer_l or "google trust" in issuer_l:
        return "Cloud CA"
    if "incommon" in issuer_l:
        return "Enterprise CA"
    if "traefik" in issuer_l or issuer_raw == "CN=TRAEFIK DEFAULT CERT":
        return "Dev / Default Cert"
    return "Unknown CA"


def _is_tls_probe_port(port) -> bool:
    if port is None:
        return False
    try:
        return int(port) == 443
    except (TypeError, ValueError):
        return str(port).strip() == "443"


def _ssl_probe_candidate_ips(assets: list[dict], limit: int) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for a in assets:
        if not a:
            continue
        ip = a.get("ip")
        if not ip:
            continue
        if _is_tls_probe_port(a.get("port")) or a.get("https_exposed"):
            s = str(ip)
            if s not in seen:
                seen.add(s)
                out.append(s)
    return out[:limit]


def _enrich_banner(rows: list[dict]) -> list[dict]:
    """Run the banner parser on each row, populating ``banner_*`` + ``cpe``."""
    for asset in rows:
        parsed = parse_banner(asset.get("banner", ""), asset.get("port"))
        asset["banner_service"] = parsed["service"]
        asset["banner_vendor"] = parsed.get("vendor")
        asset["banner_product"] = parsed["product"]
        asset["banner_version"] = parsed["version"]
        asset["banner_summary"] = parsed["summary"]
        asset["cpe"] = parsed.get("cpe")
    return rows


_STOPWORDS = {
    "unknown", "service", "server", "http", "https", "tcp", "udp", "ssl", "tls",
}


def _tokens(text: str) -> set[str]:
    text = (text or "").strip().lower().replace("_", " ").replace("/", " ").replace("-", " ")
    return {tok for tok in text.split() if tok and tok not in _STOPWORDS and len(tok) > 2}


def _index_cves_by_host(cves: list[dict], hosts: list[dict]) -> dict[str, list[dict]]:
    """Group CVE matches by host IP via product-token overlap.

    A CVE is attributed to a host only if at least one distinctive token
    in the CVE's service label appears in the host's banner_vendor /
    banner_product set. This avoids the substring overcorrelation that
    would otherwise attach every "openssh" CVE to every host that ever
    served the string "ssh".
    """
    host_tokens: dict[str, set[str]] = {}
    for h in hosts:
        ip = h.get("ip")
        if not ip:
            continue
        bag: set[str] = set()
        for key in ("banner_vendor", "banner_product", "service"):
            bag |= _tokens(h.get(key) or "")
        if bag:
            host_tokens[ip] = bag

    by_ip: dict[str, list[dict]] = defaultdict(list)
    for cve in cves or []:
        cve_tokens = _tokens(cve.get("service") or "")
        if not cve_tokens:
            continue
        for ip, htoks in host_tokens.items():
            # Require at least one substantive shared token.
            if cve_tokens & htoks:
                by_ip[ip].append(cve)
    return dict(by_ip)


def _index_certs_by_host(certs: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = defaultdict(list)
    for c in certs or []:
        ip = c.get("ip")
        if ip:
            out[ip].append(c)
    return dict(out)


def _normalize_ssl_rows(rows: list[dict]) -> list[dict]:
    for cert in rows:
        issuer_raw = cert.get("issuer", "")
        subject_raw = cert.get("subject", "")
        issuer = _parse_dn(issuer_raw)
        subject = _parse_dn(subject_raw)

        cert["issuer_name"] = issuer["summary"]
        cert["subject_name"] = subject["summary"]
        cert["issuer_cn"] = issuer["cn"]
        cert["subject_cn"] = subject["cn"]

        san = cert.get("san") or cert.get("sans") or []
        if isinstance(san, str):
            san = [san]
        cert["san_clean"] = san

        cert["trust"] = _classify_trust(issuer_raw)
    return rows


def run_pipeline(use_api: bool = False) -> dict:
    """Collect, enrich, score, and cache OSINT data.

    Returns the cached/refreshed payload. When ``use_api`` is true the
    external APIs are hit (subject to credentials being present); otherwise
    the most recent cache is returned.
    """
    settings = load_settings()
    cached = read_json(settings.cache_file) or {}
    censys_cached = read_json(settings.censys_cache_file)
    notices: list[str] = []
    dashboard: dict = {"shodan": [], "censys": [], "ssl_tls": [], "cves": []}

    # ---------------- HOST COLLECTION ----------------
    if use_api or not cached:
        if use_api or not cached.get("shodan"):
            new_shodan, shodan_err = collect_shodan()
        else:
            new_shodan, shodan_err = cached.get("shodan", []), None

        if use_api or not censys_cached:
            new_censys, censys_err = collect_censys()
        else:
            new_censys, censys_err = (
                censys_cached if isinstance(censys_cached, list) else []
            ), None

        if shodan_err:
            notices.append(shodan_err)
        if censys_err:
            notices.append(censys_err)

        if use_api and cached:
            if not new_shodan and cached.get("shodan"):
                new_shodan = list(cached["shodan"])
                notices.append("Showing cached Shodan results from the previous successful scan.")
            if not new_censys and isinstance(censys_cached, list) and censys_cached:
                new_censys = list(censys_cached)
                notices.append("Showing cached Censys results from the previous successful scan.")

        dashboard["shodan"] = new_shodan
        dashboard["censys"] = new_censys

        try:
            write_json(settings.censys_cache_file, dashboard["censys"])
        except OSError as exc:
            log.warning("could not persist censys cache: %s", exc)
    else:
        dashboard["shodan"] = cached.get("shodan", [])
        dashboard["censys"] = censys_cached if isinstance(censys_cached, list) else cached.get("censys", [])
        dashboard["ssl_tls"] = cached.get("ssl_tls", [])
        dashboard["cves"] = cached.get("cves", [])

    # ---------------- BANNER + INVENTORY + NORMALIZATION ----------------
    inventory = load_inventory()
    for source in ("shodan", "censys"):
        rows = dashboard.get(source) or []
        rows = _enrich_banner(rows)
        rows = normalize_data(rows)
        rows = compare_with_inventory(rows, inventory)
        for asset in rows:
            asset["source"] = source
            asset.update(build_service_intel(asset))
        dashboard[source] = rows

    # ---------------- CVE COLLECTION ----------------
    all_hosts = dashboard["shodan"] + dashboard["censys"]
    need_cve_fetch = use_api or not cached.get("cves")
    if need_cve_fetch:
        try:
            dashboard["cves"] = collect_cves(all_hosts)
        except Exception as exc:  # noqa: BLE001
            log.error("CVE collection failed: %s", exc)
            dashboard["cves"] = cached.get("cves", []) if cached else []
            if cached.get("cves"):
                notices.append("CVE collection failed — showing cached results.")

    # Always re-enrich the CVE list with KEV + EPSS so stale caches get
    # the latest exploitation telemetry without a full NVD re-fetch.
    try:
        from .collectors import _annotate_kev_and_epss
        _annotate_kev_and_epss(dashboard.get("cves") or [])
    except Exception as exc:  # noqa: BLE001 — KEV/EPSS are best-effort
        log.warning("KEV/EPSS enrichment skipped (%s)", exc)

    # ---------------- SSL/TLS ----------------
    if use_api or "ssl_tls" not in cached:
        hosts = _ssl_probe_candidate_ips(all_hosts, settings.ssl_probe_limit)
        fresh_ssl = collect_ssl_data(hosts) if hosts else []
        if use_api and cached and not fresh_ssl and cached.get("ssl_tls"):
            dashboard["ssl_tls"] = list(cached["ssl_tls"])
            notices.append("SSL/TLS probe found no reachable hosts — showing cached results.")
        else:
            dashboard["ssl_tls"] = fresh_ssl
    else:
        dashboard["ssl_tls"] = cached.get("ssl_tls", [])

    dashboard["ssl_tls"] = _normalize_ssl_rows(dashboard.get("ssl_tls", []))

    # ---------------- RISK SCORING (per host, against the catalog) -------
    cves_by_ip = _index_cves_by_host(dashboard["cves"], all_hosts)
    certs_by_ip = _index_certs_by_host(dashboard["ssl_tls"])
    snapshots = build_snapshots(all_hosts, cves_by_ip=cves_by_ip, certs_by_ip=certs_by_ip)
    summaries = {ip: score_snapshot(snap) for ip, snap in snapshots.items()}

    for source in ("shodan", "censys"):
        dashboard[source] = attach_per_row(dashboard[source], snapshots, summaries)

    dashboard["host_summaries"] = list(summaries.values())

    # ---------------- PERSIST ----------------
    try:
        write_json(settings.cache_file, dashboard)
    except OSError as exc:
        log.error("could not persist dashboard cache: %s", exc)

    dashboard["_pipeline_notices"] = notices
    dashboard["_cache_freshness"] = (
        read_freshness(settings.cache_file).isoformat()
        if read_freshness(settings.cache_file)
        else None
    )
    return dashboard
