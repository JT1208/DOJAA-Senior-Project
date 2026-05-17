// Intelligence view: threat feeds, IOCs, active campaigns, risk summaries, and correlated anomalies.
// Only threat-type entities appear here. Provides aggregated risk overview at the top.

import { EntityType, SEVERITY_COLOR } from '../schema.js';
import { DataTable } from '../ui/table.js';

export function mount(container, store, { onSelect } = {}) {
  container.innerHTML = '';

  const header = document.createElement('div');
  header.className = 'view-header';
  header.innerHTML = '<h2>Intelligence <span class="view-desc">Threat intelligence: active campaigns, IOCs, risk indicators, and correlations</span></h2>';
  container.appendChild(header);

  // Risk summary cards
  const summarySection = document.createElement('div');
  summarySection.className = 'intel-summary';
  container.appendChild(summarySection);

  const table = new DataTable({
    columns: [
      {
        key: 'severity', label: 'Severity',
        render: v => `<span class="sev-badge sev-${v}" style="background:${SEVERITY_COLOR[v] ?? '#888'}">${v.toUpperCase()}</span>`,
      },
      {
        key: 'category', label: 'Category',
        render: v => `<span class="threat-cat-badge cat-${v}">${v}</span>`,
      },
      {
        key: 'title', label: 'Title',
        render: v => `<strong>${v}</strong>`,
      },
      {
        key: 'indicators', label: 'IOCs',
        render: (v) => {
          if (!v?.length) return '<span class="muted">0</span>';
          const types = v.reduce((acc, i) => { acc[i.type] = (acc[i.type] || 0) + 1; return acc; }, {});
          return Object.entries(types).map(([t, n]) => `<span class="ioc-count">${n} ${t}</span>`).join(' ');
        },
        sortable: false, searchable: false,
      },
      {
        key: 'firstSeen', label: 'First Seen',
        render: v => v ? new Date(v).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }) : '—',
      },
      {
        key: 'lastSeen', label: 'Last Seen',
        render: v => v ? new Date(v).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }) : '—',
      },
      {
        key: 'source', label: 'Source',
        render: v => `<span class="source-badge src-${v.replace(/[^a-z0-9]/gi, '-')}">${v}</span>`,
        sortable: false,
      },
    ],
    onRowClick: entity => onSelect?.(entity),
    emptyMessage: 'No threat intelligence found. Load data or adjust filters.',
  });

  table.addFilter('severity', 'All Severities', [
    { value: 'critical', label: 'Critical' },
    { value: 'high', label: 'High' },
    { value: 'medium', label: 'Medium' },
    { value: 'low', label: 'Low' },
  ]);
  table.addFilter('category', 'All Categories', [
    { value: 'scanner', label: 'Scanner' },
    { value: 'c2', label: 'C2' },
    { value: 'phishing', label: 'Phishing' },
    { value: 'malware', label: 'Malware' },
    { value: 'botnet', label: 'Botnet' },
    { value: 'anomaly', label: 'Anomaly' },
  ]);

  container.appendChild(table.el);

  function renderSummary() {
    const threats = store.getAll(EntityType.THREAT);
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    const byCategory = {};
    let totalIocs = 0;

    for (const t of threats) {
      if (t.severity in bySeverity) bySeverity[t.severity]++;
      byCategory[t.category] = (byCategory[t.category] || 0) + 1;
      totalIocs += t.indicators.length;
    }

    summarySection.innerHTML = `
      <div class="intel-stat-card stat-critical">
        <div class="stat-val">${bySeverity.critical}</div>
        <div class="stat-lbl">Critical Threats</div>
      </div>
      <div class="intel-stat-card stat-high">
        <div class="stat-val">${bySeverity.high}</div>
        <div class="stat-lbl">High Threats</div>
      </div>
      <div class="intel-stat-card stat-neutral">
        <div class="stat-val">${totalIocs}</div>
        <div class="stat-lbl">Total IOCs</div>
      </div>
      <div class="intel-stat-card stat-neutral">
        <div class="stat-val">${threats.length}</div>
        <div class="stat-lbl">Active Campaigns</div>
      </div>
    `;
  }

  function refresh() {
    renderSummary();
    const data = store.getAll(EntityType.THREAT);
    data.sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return (order[a.severity] ?? 9) - (order[b.severity] ?? 9);
    });
    table.setData(data);
  }

  store.addEventListener('change:threat', refresh);
  refresh();

  return () => store.removeEventListener('change:threat', refresh);
}
