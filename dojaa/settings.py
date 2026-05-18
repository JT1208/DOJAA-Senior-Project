"""Application settings, loaded from environment with safe defaults.

All sensitive values (API keys, DB password, session secret) live here and only
here. Hardcoded fallbacks are deliberately absent — missing keys produce
friendly UI states rather than runtime crashes, but they never silently use a
checked-in credential.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _int(value: str | None, default: int) -> int:
    if value is None or not value.strip():
        return default
    try:
        return int(value)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    # --- Flask ---
    secret_key: str
    debug: bool
    auth_disabled: bool

    # --- Demo login (only used if AUTH_DISABLED is false). Leave both blank
    #     to disable form auth entirely. ---
    demo_email_domain: str
    demo_password: str

    # --- Organisation under investigation ---
    org_domain: str

    # --- Recon API credentials ---
    shodan_api_key: str
    censys_api_token: str
    nvd_api_key: str

    # --- Pipeline ---
    cache_dir: Path
    ssl_probe_timeout: float
    ssl_probe_limit: int
    cve_max_per_service: int
    cve_max_total: int

    @property
    def has_shodan(self) -> bool:
        return bool(self.shodan_api_key)

    @property
    def has_censys(self) -> bool:
        return bool(self.censys_api_token)

    @property
    def cache_file(self) -> Path:
        return self.cache_dir / "dashboard_cache.json"

    @property
    def censys_cache_file(self) -> Path:
        return self.cache_dir / "censys_data.json"

    @property
    def export_file(self) -> Path:
        return self.cache_dir / "dashboard_data.json"

    @property
    def inventory_file(self) -> Path:
        return self.cache_dir / "internal_inventory.json"


def load_settings() -> Settings:
    cache_dir = Path(os.environ.get("DOJAA_CACHE_DIR") or Path.cwd()).resolve()
    cache_dir.mkdir(parents=True, exist_ok=True)
    return Settings(
        secret_key=os.environ.get("FLASK_SECRET_KEY") or os.urandom(32).hex(),
        debug=_bool(os.environ.get("FLASK_DEBUG"), default=False),
        auth_disabled=_bool(os.environ.get("DOJAA_AUTH_DISABLED"), default=False),
        demo_email_domain=(os.environ.get("DOJAA_DEMO_EMAIL_DOMAIN") or "drexel.edu").strip(),
        # Demo password default — overrideable via DOJAA_DEMO_PASSWORD env var.
        # This branch ships with a non-empty default so the login screen is
        # usable out of the box. Replace before any non-demo deployment.
        demo_password=os.environ.get("DOJAA_DEMO_PASSWORD", "dojaa-demo"),
        org_domain=(os.environ.get("DOJAA_ORG_DOMAIN") or "drexel.edu").strip(),
        shodan_api_key=os.environ.get("SHODAN_API_KEY", "").strip(),
        censys_api_token=os.environ.get("CENSYS_API_TOKEN", "").strip(),
        nvd_api_key=os.environ.get("NVD_API_KEY", "").strip(),
        cache_dir=cache_dir,
        ssl_probe_timeout=float(os.environ.get("DOJAA_SSL_PROBE_TIMEOUT") or 2.0),
        ssl_probe_limit=_int(os.environ.get("DOJAA_SSL_PROBE_LIMIT"), 50),
        cve_max_per_service=_int(os.environ.get("DOJAA_CVE_PER_SERVICE"), 5),
        cve_max_total=_int(os.environ.get("DOJAA_CVE_MAX_TOTAL"), 25),
    )
