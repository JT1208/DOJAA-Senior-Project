# DOJAA — Digital Observatory for Joint Asset Analysis

External-attack-surface dashboard. Pulls infrastructure intelligence from
Shodan, Censys, and the NVD; enriches with banner parsing, TLS probing,
inventory diff, and risk scoring; presents it through a Flask + Bootstrap
dashboard with a PDF report.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env — at minimum set SHODAN_API_KEY and CENSYS_API_TOKEN
#                       and a non-empty DOJAA_DEMO_PASSWORD
export $(grep -v '^#' .env | xargs)

flask --app app run
# → http://127.0.0.1:5000/
```

Sign in at `/login` with:
- **Email**: anything ending in `@drexel.edu` (e.g. `demo@drexel.edu`)
- **Password**: `dojaa-demo` (this is the default; override by setting `DOJAA_DEMO_PASSWORD` in your `.env`)

To bypass auth in local development:
```bash
DOJAA_AUTH_DISABLED=true flask --app app run
```

## Architecture

```
app.py              # thin entrypoint → dojaa.create_app()
run.py              # CLI: run pipeline once, print summary
dojaa/
  __init__.py       # create_app() factory
  settings.py       # env-backed Settings
  config.py         # legacy shim for collectors
  blueprints/       # one Flask blueprint per nav tab
    auth, dashboard, hosts, ports, risk, cves,
    ssl_tls, graph, tools, reports
  services/
    cache.py        # atomic JSON writes + freshness metadata
  collectors.py     # Shodan / Censys / NVD
  enrichment/       # banner_parser, service_intel
  ssl_tls_collector.py
  normalizer.py
  risk_engine.py    # 0–100 scoring
  risk_tiers.py
  inventory.py
  robots_txt.py
  pipeline.py       # orchestrates collect → enrich → score → cache
  report_pdf.py     # ReportLab PDF
  writeToDb.py      # optional Postgres loader (CLI; web app does not touch DB)
static/
  css/{tokens,base,components}.css   # design tokens + shared components
  js/common/{api,dom,datatable,charts,nav}.js
  js/pages/{dashboard,hosts,ports,risk,cves,ssl_tls,graph,dns,headers}.js
templates/
  base.html
  partials/{_nav,_flash,_freshness,_rescan,_empty}.html
  auth/  hosts/  ports/  risk/  cves/  ssl_tls/  graph/  tools/
```

### Tab responsibilities (no overlap)

| Tab | Owns |
|-----|------|
| **Dashboard** | Executive KPIs and deep links. Zero detail tables. |
| **Hosts** | The combined Shodan + Censys inventory. **Sole** owner of host actions: search, source filter, risk filter, port filter, rescan, CSV export, drilldown to `/hosts/<ip>`. |
| **Ports** | Port-distribution analytics (most exposed ports, service mix, risky-host count per port). |
| **Risk** | Tier distribution, top-N risky assets (linked to host detail, not duplicated), driver frequency. |
| **CVEs** | All CVE findings with NVD / CWE / CISA-KEV remediation guidance. |
| **SSL/TLS** | Certificate intelligence with colour-coded expiry. IP links to host detail. |
| **Graph** | vis-network attack-surface view. Double-click a host node to open detail. |
| **Tools → DNS** | DNS-over-HTTPS lookup for any domain (Google resolver). |
| **Tools → Headers** | OWASP HTTP security-header check for any URL. |
| **Tools → Robots.txt** | Disallow-path tree for any host. |
| **Reports** | One-click PDF download of the current dashboard data. |

## Data sources

All data comes from official, documented APIs. There is no mock / fake data.

| API | Used by | Auth | Falls back when missing |
|-----|---------|------|-------------------------|
| [Shodan](https://developer.shodan.io/api) | Hosts (primary collector) | `SHODAN_API_KEY` | empty list + UI notice |
| [Censys v2](https://search.censys.io/api) | Hosts (secondary collector) | `CENSYS_API_TOKEN` (Basic auth, empty password per Censys docs) | empty list + UI notice |
| [NVD 2.0](https://nvd.nist.gov/developers) | CVEs | optional `NVD_API_KEY` (raises 5 → 50 req / 30 s) | unauthenticated mode |
| [Google DNS-over-HTTPS](https://developers.google.com/speed/public-dns/docs/doh) | Tools → DNS | none | n/a |
| Direct TLS handshake on :443 | SSL/TLS | none | n/a |
| Direct HTTP GET | Tools → Headers / Robots | none | n/a |

When a key is missing the relevant collector returns `[]` and a yellow
banner explains *which* key is missing. Nothing crashes; nothing silently
substitutes a hardcoded credential.

## Configuration reference

See [.env.example](.env.example). All settings are env-backed; nothing is
hardcoded. Key knobs:

| Variable | Default | Purpose |
|----------|---------|---------|
| `FLASK_SECRET_KEY` | random per startup | session signing |
| `FLASK_DEBUG` | `false` | enable Flask debug mode |
| `DOJAA_AUTH_DISABLED` | `false` | bypass `/login` (dev only) |
| `DOJAA_DEMO_EMAIL_DOMAIN` | `drexel.edu` | login email-domain whitelist |
| `DOJAA_DEMO_PASSWORD` | `""` | login password (empty = form auth disabled) |
| `DOJAA_ORG_DOMAIN` | `drexel.edu` | recon query target |
| `SHODAN_API_KEY` | — | required for Shodan collection |
| `CENSYS_API_TOKEN` | — | required for Censys collection |
| `NVD_API_KEY` | — | optional, raises CVE rate limit |
| `DOJAA_CACHE_DIR` | CWD | where pipeline writes JSON caches |
| `DOJAA_SSL_PROBE_TIMEOUT` | `2.0` | per-host TLS handshake timeout (s) |
| `DOJAA_SSL_PROBE_LIMIT` | `50` | max hosts to probe per run |
| `DOJAA_CVE_PER_SERVICE` | `5` | NVD `resultsPerPage` per service |
| `DOJAA_CVE_MAX_TOTAL` | `25` | hard cap on CVE rows |

## Pipeline behaviour

`run_pipeline(use_api=True)` runs collect → enrich → score → cache.
`use_api=False` (the default) reads the most recent cache.

The pipeline degrades gracefully:
- missing API key → empty result + UI notice
- API returns empty + cache exists → cache used + UI notice
- cache write fails → logged but does not raise

Cache files live in `DOJAA_CACHE_DIR` (default: CWD):
- `dashboard_cache.json` — full enriched payload
- `censys_data.json` — raw Censys snapshot (used as secondary cache)
- `*.meta` — ISO timestamps of the last successful write (powers the
  "Data refreshed N minutes ago" indicator)

Writes are atomic (write to `*.tmp` then `os.replace`).

## Security follow-ups

The previous branch checked the following credentials into source. They are
**still leaked on GitHub** — the env migration here does not retroactively
remove them. Please rotate before considering this production-ready:

1. Shodan API key previously at `dojaa/config.py:6`
2. Both Censys tokens previously at `dojaa/config.py:8-9`
3. Postgres password previously at `dojaa/config.py:21`
4. Set a real `FLASK_SECRET_KEY` (was `"supersecretkey"`)
5. Replace the demo `Drexel123!` password with a per-deployment value

## Development

```bash
# Run pipeline once, print summary
python run.py

# Run app
flask --app app run --debug

# Smoke-test every route
python -c "
from dojaa import create_app
app = create_app()
c = app.test_client()
for p in ['/dashboard','/hosts','/ports','/risk','/cves','/ssl-tls','/graph','/tools/dns','/tools/headers','/tools/robots']:
    print(c.get(p).status_code, p)
"
```
