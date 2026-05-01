"""Fetch and parse robots.txt for a host (used by the Robots dashboard page)."""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import tempfile
from urllib.parse import urljoin

import requests


def _resolve_site_base(site: str, session: requests.Session, timeout: int = 12) -> str | None:
    site = (site or "").strip().strip("/")
    if not site:
        return None

    def try_get(url: str) -> str | None:
        try:
            r = session.get(url, timeout=timeout, allow_redirects=True)
            if r.url:
                u = r.url.rstrip("/") + "/"
                return u
        except Exception:
            return None
        return None

    try:
        ipaddress.ip_address(site)
        for scheme in ("https", "http"):
            base = try_get(f"{scheme}://{site}")
            if base:
                return base
        return None
    except ValueError:
        pass

    if "://" in site:
        return try_get(site)

    for prefix in (f"https://{site}", f"http://{site}"):
        base = try_get(prefix)
        if base:
            return base
    return None


def _parse_robots_txt(text: str) -> dict[str, list[tuple[bool, str]]]:
    """Return mapping User-agent -> list of (is_allow, path)."""
    rules: dict[str, list[tuple[bool, str]]] = {}
    current_agents: list[str] = []
    last_line_was_user_agent = False

    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            last_line_was_user_agent = False
            continue
        m = re.match(r"(?i)^(user-agent|disallow|allow)\s*:\s*(.*)$", line)
        if not m:
            last_line_was_user_agent = False
            continue
        kind, rest = m.group(1).lower(), m.group(2).strip()
        if kind == "user-agent":
            if last_line_was_user_agent:
                if rest:
                    current_agents.append(rest)
            else:
                current_agents = [rest] if rest else []
            last_line_was_user_agent = True
        elif kind == "disallow":
            last_line_was_user_agent = False
            for ag in current_agents:
                rules.setdefault(ag, []).append((False, rest))
        elif kind == "allow":
            last_line_was_user_agent = False
            for ag in current_agents:
                rules.setdefault(ag, []).append((True, rest))
    return rules


def fetch_robots_rules(
    site: str,
    timeout: int = 12,
) -> tuple[dict[str, list[tuple[bool, str]]] | None, str | None]:
    """
    Fetch robots.txt for site (hostname, optional scheme, or IP).
    Returns (rules dict or None on failure, error message or None).
    """
    with requests.Session() as session:
        base = _resolve_site_base(site, session, timeout=timeout)
        if not base:
            return None, "Could not reach host; check the site name or network."

        robots_url = urljoin(base, "robots.txt")
        try:
            r = session.get(robots_url, timeout=timeout, allow_redirects=True)
            if r.status_code >= 400:
                return None, f"robots.txt returned HTTP {r.status_code}."
            rules = _parse_robots_txt(r.text)
            return rules, None
        except Exception as e:
            return None, str(e)


def disallow_paths_for_wildcard(rules: dict[str, list[tuple[bool, str]]]) -> list[str]:
    """Paths from User-agent * Disallow entries (non-empty)."""
    out: list[str] = []
    for agent, entries in rules.items():
        if agent.strip() != "*":
            continue
        for is_allow, path in entries:
            if is_allow:
                continue
            p = (path or "").strip()
            if p:
                out.append(p)
    return out


def safe_relative_segments(path: str) -> list[str] | None:
    """
    Turn a robots path like /admin/login into safe folder segments under a temp root.
    Returns None if path should be skipped (unsafe or empty).
    """
    if not path or path == "/":
        return None
    p = path.replace("\\", "/").strip()
    if not p.startswith("/"):
        p = "/" + p
    parts = [x for x in p.strip("/").split("/") if x]
    if not parts:
        return None
    for seg in parts:
        if seg in (".", "..") or ".." in seg:
            return None
    return parts


def _ascii_tree(root: str) -> str:
    lines: list[str] = ["."]

    def walk(dir_path: str, prefix: str) -> None:
        try:
            names = sorted(os.listdir(dir_path))
        except OSError:
            return
        for i, name in enumerate(names):
            last = i == len(names) - 1
            branch = "└── " if last else "├── "
            lines.append(prefix + branch + name)
            sub = os.path.join(dir_path, name)
            if os.path.isdir(sub):
                extension = "    " if last else "│   "
                walk(sub, prefix + extension)

    walk(root, "")
    return "\n".join(lines)


def disallow_paths_tree_preview(disallow_paths: list[str]) -> str:
    """
    Materialize Disallow paths as nested empty dirs and return a tree(1)-style
    string, or a simple ASCII fallback if tree is unavailable.
    """
    with tempfile.TemporaryDirectory(prefix="dojaa_robots_") as tmp:
        for path in disallow_paths:
            segs = safe_relative_segments(path)
            if not segs:
                continue
            full = os.path.join(tmp, *segs)
            os.makedirs(full, exist_ok=True)
        try:
            result = subprocess.run(
                ["tree", tmp],
                capture_output=True,
                text=True,
                check=True,
                timeout=15,
            )
            out = (result.stdout or "").strip()
            if not out:
                return _ascii_tree(tmp)
            split = out.splitlines()
            if len(split) > 1 and split[0].rstrip("/").endswith(os.path.basename(tmp)):
                return "\n".join(split[1:]).strip() or _ascii_tree(tmp)
            return out
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return _ascii_tree(tmp)
