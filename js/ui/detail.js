// Detail Inspector panel: slide-in side panel showing entity properties + correlated entities.
// All properties display source provenance. Related entities are navigable (click to inspect).

import { EntityType, SEVERITY_COLOR } from '../schema.js';

export class DetailPanel {
  constructor(store) {
    this.store = store;
    this.el = this._build();
  }

  show(entity) {
    const badge = this.el.querySelector('#dp-badge');
    const title = this.el.querySelector('#dp-title');
    const src = this.el.querySelector('#dp-source');
    const body = this.el.querySelector('#dp-body');

    badge.textContent = entity.type.toUpperCase();
    badge.className = 'dp-type-badge dp-type-' + entity.type;
    title.textContent = this._title(entity);
    src.innerHTML = `Source: <span class="source-badge">${entity.source}</span>`;

    body.innerHTML = '';
    body.appendChild(this._renderProps(entity));
    body.appendChild(this._renderRelated(entity));

    this.el.classList.add('dp-open');
  }

  hide() {
    this.el.classList.remove('dp-open');
  }

  _build() {
    const el = document.createElement('aside');
    el.className = 'detail-panel';
    el.innerHTML = `
      <div class="dp-header">
        <div class="dp-title-row">
          <span id="dp-badge" class="dp-type-badge"></span>
          <h3 id="dp-title" class="dp-title"></h3>
        </div>
        <button class="dp-close" id="dp-close" aria-label="Close inspector">×</button>
      </div>
      <div id="dp-source" class="dp-source"></div>
      <div id="dp-body" class="dp-body"></div>
    `;
    el.querySelector('#dp-close').addEventListener('click', () => this.hide());
    return el;
  }

  _title(e) {
    switch (e.type) {
      case EntityType.HOST: return e.hostname || e.ip;
      case EntityType.DOMAIN: return e.name;
      case EntityType.VULNERABILITY: return e.id;
      case EntityType.CERTIFICATE: return e.subject;
      case EntityType.THREAT: return e.title;
      default: return e.id;
    }
  }

  _renderProps(e) {
    const sec = document.createElement('section');
    sec.className = 'dp-section';
    const h4 = document.createElement('h4');
    h4.textContent = 'Properties';
    sec.appendChild(h4);

    const dl = document.createElement('dl');
    dl.className = 'dp-props';

    for (const [label, value] of this._propsFor(e)) {
      if (value == null || value === '') continue;
      const dt = document.createElement('dt');
      dt.textContent = label;
      const dd = document.createElement('dd');
      if (value instanceof Node) dd.appendChild(value);
      else dd.innerHTML = String(value);
      dl.append(dt, dd);
    }

    sec.appendChild(dl);
    return sec;
  }

  _propsFor(e) {
    const fmt = v => v ? new Date(v).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }) : null;
    const tags = ts => ts?.length ? ts.map(t => `<span class="tag">${t}</span>`).join(' ') : null;
    const sev = s => `<span class="sev-badge sev-${s}" style="background:${SEVERITY_COLOR[s] ?? '#888'}">${s.toUpperCase()}</span>`;
    const refs = rs => rs?.length
      ? rs.map(r => `<a href="${r}" target="_blank" rel="noopener" class="ref-link">${r}</a>`).join('<br>')
      : null;

    switch (e.type) {
      case EntityType.HOST:
        return [
          ['IP Address', `<span class="mono">${e.ip}</span>`],
          ['Hostname', e.hostname],
          ['Operating System', e.os],
          ['Country', e.country],
          ['ASN / Org', [e.asn, e.org].filter(Boolean).join(' · ')],
          ['Open Ports', e.ports.length ? e.ports.map(p => `<span class="port-badge">${p.port}/${p.protocol}</span>`).join(' ') : null],
          ['Services', e.services.map(s => `${s.product || s.name} ${s.version || ''}`.trim()).join(', ') || null],
          ['Last Seen', fmt(e.lastSeen)],
          ['Tags', tags(e.tags)],
        ];
      case EntityType.DOMAIN:
        return [
          ['Domain', e.name],
          ['Registrar', e.registrar],
          ['Created', fmt(e.created)],
          ['Expires', fmt(e.expires)],
          ['IP Addresses', e.ips.join(', ') || null],
          ['Subdomains', e.subdomains.join(', ') || null],
          ['DNS Records', this._renderDnsRecords(e.records)],
          ['Tags', tags(e.tags)],
        ];
      case EntityType.VULNERABILITY:
        return [
          ['CVE ID', `<a href="https://nvd.nist.gov/vuln/detail/${e.id}" target="_blank" rel="noopener">${e.id}</a>`],
          ['Severity', sev(e.severity)],
          ['CVSS Score', e.cvss != null ? `${e.cvss}${e.cvssVector ? ' · ' + e.cvssVector : ''}` : null],
          ['CWE', e.cwe],
          ['Published', fmt(e.published)],
          ['Affected Products', e.affectedProducts.join('; ') || null],
          ['Description', `<p class="dp-desc">${e.description}</p>`],
          ['References', refs(e.references)],
          ['Tags', tags(e.tags)],
        ];
      case EntityType.CERTIFICATE:
        return [
          ['Subject', e.subject],
          ['Issuer', e.issuer],
          ['Domains (SANs)', e.domains.join(', ') || null],
          ['Valid From', fmt(e.validFrom)],
          ['Valid To', e.isExpired
            ? `<span class="text-danger">${fmt(e.validTo)} — EXPIRED</span>`
            : (e.daysUntilExpiry != null && e.daysUntilExpiry <= 30)
              ? `<span class="text-warning">${fmt(e.validTo)} (${e.daysUntilExpiry}d remaining)</span>`
              : fmt(e.validTo)],
          ['Algorithm', e.algorithm],
          ['Fingerprint', e.fingerprint ? `<span class="mono small">${e.fingerprint}</span>` : null],
          ['Serial Number', e.serialNumber ? `<span class="mono small">${e.serialNumber}</span>` : null],
          ['Tags', tags(e.tags)],
        ];
      case EntityType.THREAT:
        return [
          ['Category', e.category],
          ['Severity', sev(e.severity)],
          ['First Seen', fmt(e.firstSeen)],
          ['Last Seen', fmt(e.lastSeen)],
          ['Description', `<p class="dp-desc">${e.description}</p>`],
          ['Indicators', this._renderIndicators(e.indicators)],
          ['References', refs(e.references)],
          ['Tags', tags(e.tags)],
        ];
      default:
        return [];
    }
  }

  _renderRelated(entity) {
    const sec = document.createElement('section');
    sec.className = 'dp-section';
    const h4 = document.createElement('h4');
    h4.textContent = 'Related Intelligence';
    sec.appendChild(h4);

    const correlations = this.store.getCorrelationsFor(entity.type, entity.id);
    if (!correlations.length) {
      const p = document.createElement('p');
      p.className = 'dp-empty';
      p.textContent = 'No correlated entities found.';
      sec.appendChild(p);
      return sec;
    }

    // Group by relation label + entity type
    const groups = new Map();
    for (const c of correlations) {
      const isFrom = c.fromType === entity.type && c.fromId === entity.id;
      const otherType = isFrom ? c.toType : c.fromType;
      const otherId = isFrom ? c.toId : c.fromId;
      const relation = c.relation;
      const key = `${relation}::${otherType}`;
      if (!groups.has(key)) groups.set(key, { relation, type: otherType, items: [] });
      const other = this.store.getById(otherType, otherId);
      if (other) groups.get(key).items.push(other);
    }

    for (const { relation, type, items } of groups.values()) {
      const grp = document.createElement('div');
      grp.className = 'dp-corr-group';

      const lbl = document.createElement('div');
      lbl.className = 'dp-corr-label';
      lbl.innerHTML = `<span class="dp-corr-rel">${relation}</span> <span class="dp-type-chip dp-type-${type}">${type}</span>`;
      grp.appendChild(lbl);

      const ul = document.createElement('ul');
      ul.className = 'dp-corr-list';
      for (const related of items) {
        const li = document.createElement('li');
        const btn = document.createElement('button');
        btn.className = 'dp-corr-link';
        btn.textContent = this._title(related);
        btn.addEventListener('click', () => this.show(related));
        li.appendChild(btn);
        ul.appendChild(li);
      }
      grp.appendChild(ul);
      sec.appendChild(grp);
    }

    return sec;
  }

  _renderDnsRecords(records) {
    if (!records?.length) return null;
    const wrap = document.createElement('div');
    wrap.className = 'dns-records';
    for (const r of records) {
      const row = document.createElement('div');
      row.className = 'dns-record';
      row.innerHTML = `<span class="dns-type">${r.type}</span><span class="dns-val">${r.value}</span>`;
      wrap.appendChild(row);
    }
    return wrap;
  }

  _renderIndicators(indicators) {
    if (!indicators?.length) return null;
    const wrap = document.createElement('div');
    wrap.className = 'ioc-list';
    for (const ioc of indicators) {
      const row = document.createElement('div');
      row.className = 'ioc-row';
      row.innerHTML = `<span class="ioc-type">${ioc.type}</span><span class="mono">${ioc.value}</span>`;
      wrap.appendChild(row);
    }
    return wrap;
  }
}
