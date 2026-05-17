// Vulnerabilities view: CVE records, CVSS scores, affected products, and authoritative references.
// Only vulnerability-type entities appear here. Supports CSV upload to ingest additional CVE data.

import { EntityType, SEVERITY_COLOR, SEVERITY_ORDER } from '../schema.js';
import { DataTable } from '../ui/table.js';
import { loadCsvFile } from '../adapters/cve-csv.js';
import { buildCorrelations } from '../correlations.js';

export function mount(container, store, { onSelect } = {}) {
  container.innerHTML = '';

  // Header with CSV upload action
  const header = document.createElement('div');
  header.className = 'view-header view-header-actions';
  header.innerHTML = `
    <h2>Vulnerabilities <span class="view-desc">CVE records, severity scoring, and affected product mapping</span></h2>
    <div class="view-actions">
      <label class="btn-upload" for="cve-csv-input" title="Upload a CVE CSV file to add vulnerabilities">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
        </svg>
        Upload CVE CSV
      </label>
      <input type="file" id="cve-csv-input" accept=".csv,text/csv" class="hidden-file-input">
      <span id="csv-status" class="csv-status"></span>
    </div>
  `;
  container.appendChild(header);

  const table = new DataTable({
    columns: [
      {
        key: 'id', label: 'CVE ID',
        render: (v, item) => {
          const isNvd = v.startsWith('CVE-');
          return isNvd
            ? `<a href="https://nvd.nist.gov/vuln/detail/${v}" target="_blank" rel="noopener" class="cve-link">${v}</a>`
            : `<span class="mono">${v}</span>`;
        },
      },
      {
        key: 'title', label: 'Title',
        render: v => `<span class="vuln-title">${v}</span>`,
      },
      {
        key: 'severity', label: 'Severity',
        render: v => `<span class="sev-badge sev-${v}" style="background:${SEVERITY_COLOR[v] ?? '#888'}">${v.toUpperCase()}</span>`,
      },
      {
        key: 'cvss', label: 'CVSS',
        render: v => v != null ? `<span class="cvss-score cvss-${cvssClass(v)}">${v.toFixed(1)}</span>` : '<span class="muted">—</span>',
      },
      {
        key: 'affectedProducts', label: 'Affected Products',
        render: v => v?.length
          ? v.slice(0, 2).map(p => `<span class="product-tag">${p}</span>`).join(' ') + (v.length > 2 ? `<span class="muted"> +${v.length - 2}</span>` : '')
          : '<span class="muted">—</span>',
        searchable: false,
      },
      {
        key: 'published', label: 'Published',
        render: v => v ? new Date(v).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }) : '—',
      },
      {
        key: 'source', label: 'Source',
        render: v => `<span class="source-badge src-${v.replace(/[^a-z0-9]/gi, '-')}">${v}</span>`,
        sortable: false,
      },
    ],
    onRowClick: entity => onSelect?.(entity),
    emptyMessage: 'No vulnerabilities found. Upload a CVE CSV or load demo data.',
    pageSize: 15,
  });

  table.addFilter('severity', 'All Severities', [
    { value: 'critical', label: 'Critical' },
    { value: 'high', label: 'High' },
    { value: 'medium', label: 'Medium' },
    { value: 'low', label: 'Low' },
  ]);
  table.addFilter('source', 'All Sources', [
    { value: 'nvd', label: 'NVD' },
    { value: 'csv-upload', label: 'CSV Upload' },
    { value: 'mock', label: 'Demo' },
  ]);

  container.appendChild(table.el);

  // CSV upload handler
  const csvInput = header.querySelector('#cve-csv-input');
  const csvStatus = header.querySelector('#csv-status');

  csvInput.addEventListener('change', async () => {
    const file = csvInput.files?.[0];
    if (!file) return;
    csvStatus.textContent = 'Parsing…';
    csvStatus.className = 'csv-status';
    try {
      const vulns = await loadCsvFile(file);
      store.append(EntityType.VULNERABILITY, vulns);
      store.setCorrelations(buildCorrelations(store));
      csvStatus.textContent = `✓ Loaded ${vulns.length} CVEs`;
      csvStatus.className = 'csv-status success';
    } catch (err) {
      csvStatus.textContent = `Error: ${err.message}`;
      csvStatus.className = 'csv-status error';
    } finally {
      csvInput.value = '';
    }
  });

  function refresh() {
    const data = store.getAll(EntityType.VULNERABILITY);
    // Sort by severity by default
    data.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));
    table.setData(data);
  }

  store.addEventListener('change:vulnerability', refresh);
  refresh();

  return () => store.removeEventListener('change:vulnerability', refresh);
}

function cvssClass(score) {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}
