"""Legacy module-level constants kept for backward compatibility.

New code should import :class:`dojaa.settings.Settings` instead.

No credentials are checked in. Provide them via environment variables (see
``.env.example``). When a key is empty the relevant collector returns an empty
result set and the UI surfaces an explicit "missing key" notice — it does not
fall back to a hidden default.
"""

from __future__ import annotations

from .settings import load_settings

_settings = load_settings()

SHODAN_API_KEY = _settings.shodan_api_key
CENSYS_API_TOKEN = _settings.censys_api_token
CVE_API_KEY = _settings.nvd_api_key
ORG_DOMAIN = _settings.org_domain
INVENTORY_FILE = str(_settings.inventory_file)
