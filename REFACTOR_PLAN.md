# DOJAA Production Refactor Plan

Audit + plan for elevating DOJAA from a feature-branch prototype to a production-quality, competition-ready OSINT/recon console. Branch: `claude/production-refactor`.

---

## 1. What the app is

Flask web app that ingests organisation-scoped infrastructure data from external recon APIs (Shodan, Censys, NVD, Google DNS-over-HTTPS, robots.txt), enriches it (banner parsing, TLS probing, risk scoring), and presents it through a multi-tab dashboard with a PDF export.

External APIs (all real, documented, no mock data needed):
- **Shodan** `api.shodan.io/shodan/host/search`
- **Censys v2** `search.censys.io/api/v2/hosts/search`
- **NVD 2.0** `services.nvd.nist.gov/rest/json/cves/2.0`
- **Google DNS-over-HTTPS** `dns.google/resolve`
- **Direct** TLS handshake on :443 for SSL/TLS module
- **Direct** HTTPS GET on `<host>/robots.txt`
- **Direct** HTTPS HEAD/GET for HTTP security-header inspection

## 2. Audit: what each tab does vs. should do

| Tab | Current behaviour | Issue | Target |
|-----|-------------------|-------|--------|
| **Dashboard** | Hero, 2 charts, top-5 Shodan, top-5 Censys, top-25 CVEs (all duplicated elsewhere). | Duplicates Hosts/CVEs/Risk content; not a dashboard, a feed. | Pure executive overview: KPIs, freshness, recent activity, links into detail tabs. Zero detail tables. |
| **Hosts** | Shodan-only table; rescan form; links to asset detail. | Excludes Censys; doesn't own "host actions/tools" the prompt asks for. | The **sole** host-centric view: combined Shodan+Censys inventory, search, filter, drilldown, rescan, export, host-level tools. |
| **Ports** | Per-host Shodan row table with port filter. | Restates Hosts data. | Port-centric analytics: distribution by port/service, exposure trends, no per-host rehash. |
| **Risk** | Risk doughnut (= Dashboard's) + per-host table. | Restates Dashboard chart + Hosts table. | Risk-centric analytics: tier counts, top-N risky assets (linked, not duplicated), driver breakdown. |
| **CVEs** | DataTable of all CVEs with NVD/CWE/CISA links. | Mostly OK; long instructional card pushes table below the fold. | Same data, collapsible guidance, severity filter, link CVEs to affected hosts. |
| **SSL/TLS** | Cert table with risk + trust. | Days-left has no colour; IP not linked to asset; inline CSS duplicated. | Same data, colour-coded expiry, IP linked to host drilldown, extracted CSS. |
| **Graph** | vis-network graph of attack surface. | Debug `<pre>` left in; fixed 900px height; service classification hardcoded. | Clean responsive graph, legend, loading state, no debug noise. |
| **DNS Enum / Headers / Robots** | Three sibling tabs that are *tools*, not asset views. | Mixed into the asset-view nav with no grouping; HTML built via string concat (XSS risk). | Grouped under a **Tools** nav menu, shared form/result component, safe DOM rendering. |
| **Asset detail** | Reachable from Hosts only; no breadcrumb back. | Dead-end; only one tab links to it. | Reachable from Hosts/Ports/SSL/CVEs; breadcrumb back; full context (banner, CVEs hitting this asset, cert, recent change). |
| **Login** | Email + password; hardcoded `Drexel123!`. | Credential in source. | Env-configured demo creds, optional disable, clearer login screen. |
| **Logout** | Clears session. | Fine. | Unchanged. |

## 3. Architecture target

Move from monolithic `app.py` + grab-bag `dojaa/` package to clear layers.

```
dojaa/
  __init__.py             # create_app() factory
  config.py               # Settings (env-backed, validated)
  blueprints/             # Flask routes per-domain
    auth.py
    dashboard.py
    hosts.py              # host pages + host actions + per-host APIs
    ports.py
    risk.py
    cves.py
    ssl_tls.py
    graph.py
    tools.py              # DNS / robots / headers — sibling utilities
    reports.py            # PDF
  services/               # Pure business logic; no Flask imports
    pipeline.py
    collectors/
      shodan.py
      censys.py
      nvd.py
    enrichment/
      banner.py
      service_intel.py
      ssl_probe.py
    risk.py
    cache.py              # atomic cache write + freshness metadata
    dns.py
    robots.py
    headers.py
  models.py               # @dataclass schemas (Host, Cve, Cert, RiskBucket)
  utils.py
templates/
  base.html
  partials/               # _stat_card, _empty_state, _table_wrapper, _flash
  hosts/index.html
  hosts/detail.html
  ports/index.html
  risk/index.html
  cves/index.html
  ssl_tls/index.html
  graph/index.html
  tools/dns.html
  tools/robots.html
  tools/headers.html
  dashboard.html
  auth/login.html
static/
  css/
    tokens.css            # design tokens (colours, spacing, type)
    base.css              # layout + nav
    components.css        # cards, badges, tables, empty/loading
    pages/                # page-specific CSS only when justified
  js/
    common/
      api.js              # fetch helpers + error toasts
      datatable.js        # shared DataTables config
      charts.js           # shared Chart.js helpers
      dom.js              # safe text/element builders
    pages/                # one file per page
```

## 4. Phased delivery

**Phase 1 — Backend skeleton & security**
- App factory, Flask blueprints split per-domain.
- `Settings` class reading `os.environ` with `.env.example` checked in.
- Remove keys / DB password from `config.py`; document rotation in plan.
- Delete dead code (`dojaa/main.py`, `dojaa/testing.py`, `banner_grabber.py` if unused, commented blocks).
- Single entry point: `flask run` (drop `run.py`/`main.py` duplication or make them thin shims).
- Replace bare `except` with specific exceptions + `logging`.
- Atomic cache writes + freshness timestamp.

**Phase 2 — Hosts tab consolidation**
- Hosts becomes the only place host inventory + host actions live.
- Combine Shodan + Censys with source badge.
- Add: search, source filter, risk tier filter, port filter, CSV export, rescan, "open detail".
- Drilldown page enriched with: matching CVEs, matching cert, matching banner-parsed fields, "back to hosts" breadcrumb.
- Remove host listings from Dashboard / Risk / Ports.

**Phase 3 — Other-tab boundaries**
- Dashboard reduced to KPIs (count of hosts, count of high-risk, count of expiring certs <30d, count of unpatched critical CVEs), freshness, recent activity, deep links.
- Ports tab becomes port-distribution analytics (top ports, exposure-by-service, risk-by-port). No per-host row dump.
- Risk tab becomes risk-distribution analytics (tier counts, top drivers, distribution chart). No per-host row dump.
- Group DNS/Robots/Headers under "Tools" nav dropdown.

**Phase 4 — Data sources hardening**
- Env-driven API keys + clear "missing key → friendly empty state" path (no crash).
- Pydantic-free dataclass schemas validated at collector boundary.
- Source attribution on every row (`source: "shodan" | "censys"`).
- Cache freshness shown in UI everywhere.
- Optional NVD key, optional Censys key — degrade gracefully.

**Phase 5 — UI/UX polish**
- Extract every inline `<style>` and `<script>` to `static/`.
- Design tokens (CSS custom properties): brand colour, surface, border, danger/warning/success, radius, spacing scale.
- Shared partials: stat card, empty state, loading skeleton, flash toast.
- Accessibility: form labels, ARIA on badges, focus rings, keyboard nav, semantic landmarks, viewport meta, page title block.
- DataTables config centralised; pagination CSS extracted once.
- SRI hashes on CDN links.

**Phase 6 — Smoke test**
- `flask run`, click every tab, verify no regressions, commit.

## 5. Security follow-ups for the user

These cannot be fixed by code alone — **please action after the refactor**:

1. **Rotate the Shodan key** committed at `dojaa/config.py:6` — it has been public on GitHub.
2. **Rotate both Censys tokens** committed at `dojaa/config.py:8-9`.
3. **Change the Postgres password** committed at `dojaa/config.py:21`.
4. Choose a real session secret (`FLASK_SECRET_KEY`) — current value `"supersecretkey"` is a dev placeholder.
5. Replace `Drexel123!` demo login with SSO or a per-deployment env-supplied credential.

The code changes here move all of these to env vars and stop reading the old hardcoded defaults, but the credentials themselves are already leaked and must be rotated upstream.

## 6. Out of scope for this refactor

- Persistent database backing (currently file-cache based — keeping that for now, hardening it).
- Multi-user / multi-org support.
- WebSocket live updates.
- Containerisation / deploy automation.
- Comprehensive unit test suite (we add smoke import tests + a couple of pure-function tests; full coverage is its own project).
