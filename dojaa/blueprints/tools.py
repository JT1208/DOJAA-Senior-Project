"""Standalone OSINT utility tools.

These are operator-facing inputs/outputs that don't depend on the recon
pipeline: arbitrary DNS lookup, HTTP security-header check, robots.txt
explorer. They live together under ``/tools/*`` and share a Bootstrap form
layout in the templates.
"""

from __future__ import annotations

import logging
import re

import requests
from flask import Blueprint, current_app, flash, jsonify, render_template, request

from ..robots_txt import (
    disallow_paths_for_wildcard,
    disallow_paths_tree_preview,
    fetch_robots_rules,
)
from ._support import current_user, require_login

log = logging.getLogger(__name__)

bp = Blueprint("tools", __name__, url_prefix="/tools")


# A defensive host pattern: letters/digits/dots/hyphens, plus IPv4. We pass
# values to external services so we want to reject obvious garbage early.
_HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")

_SECURITY_HEADERS = (
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)

_DNS_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")


def _clean_host(value: str) -> str:
    value = (value or "").strip()
    value = re.sub(r"^https?://", "", value, flags=re.IGNORECASE)
    return value.strip("/").split("/")[0]


# ---------------- DNS ----------------


@bp.route("/dns")
@require_login
def dns():
    return render_template("tools/dns.html", user=current_user())


@bp.route("/dns/api")
@require_login
def dns_api():
    domain = _clean_host(request.args.get("domain", ""))
    if not domain or not _HOST_RE.match(domain):
        return jsonify({"error": "Enter a valid hostname (letters, digits, dots, hyphens)."}), 400

    results: dict[str, list[str]] = {}
    for rtype in _DNS_RECORD_TYPES:
        try:
            resp = requests.get(
                "https://dns.google/resolve",
                params={"name": domain, "type": rtype},
                timeout=8,
            )
            resp.raise_for_status()
            answers = resp.json().get("Answer", []) or []
            results[rtype] = [a.get("data", "") for a in answers if a.get("data")]
        except (requests.RequestException, ValueError) as exc:
            log.info("dns lookup failed for %s/%s: %s", domain, rtype, exc)
            results[rtype] = []

    return jsonify({"domain": domain, "records": results})


# ---------------- HTTP HEADER CHECK ----------------


@bp.route("/headers")
@require_login
def headers():
    return render_template("tools/headers.html", user=current_user())


@bp.route("/headers/api")
@require_login
def headers_api():
    raw = (request.args.get("url") or "").strip()
    if not raw:
        return jsonify({"error": "Enter a URL or hostname."}), 400
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw

    try:
        resp = requests.get(raw, timeout=8, allow_redirects=True)
    except requests.RequestException as exc:
        return jsonify({"error": f"Request failed: {exc}"}), 502

    results = {}
    for header in _SECURITY_HEADERS:
        value = resp.headers.get(header)
        results[header] = {"present": value is not None, "value": value or "Missing"}

    return jsonify(
        {
            "url": resp.url,
            "status_code": resp.status_code,
            "results": results,
        }
    )


# ---------------- ROBOTS.TXT ----------------


@bp.route("/robots")
@require_login
def robots():
    settings = current_app.config["DOJAA_SETTINGS"]
    site = _clean_host(request.args.get("site") or settings.org_domain)
    if not _HOST_RE.match(site):
        flash("Enter a valid hostname (letters, digits, dots, hyphens).", "warning")
        site = settings.org_domain

    rules, err = fetch_robots_rules(site)
    if err:
        flash(err, "warning")
        tree_text = ""
    elif not rules:
        tree_text = ""
    else:
        dis = disallow_paths_for_wildcard(rules)
        tree_text = (
            disallow_paths_tree_preview(dis)
            if dis
            else "(No Disallow entries for User-agent: *)"
        )

    return render_template(
        "tools/robots.html",
        user=current_user(),
        site=site,
        tree_text=tree_text,
    )
