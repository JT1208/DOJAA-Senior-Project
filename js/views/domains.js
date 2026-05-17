// Domains view: domain names, DNS records, resolution chains, registrar data, and subdomain enumeration.
// Only domain-type entities appear here. No host or vulnerability data leaks into this view.

import { EntityType } from '../schema.js';
import { DataTable } from '../ui/table.js';

export function mount(container, store, { onSelect } = {}) {
  container.innerHTML = '';

  const header = document.createElement('div');
  header.className = 'view-header';
  header.innerHTML = '<h2>Domains <span class="view-desc">DNS intelligence: records, resolution chains, and domain relationships</span></h2>';
  container.appendChild(header);

  const table = new DataTable({
    columns: [
      { key: 'name', label: 'Domain Name', render: v => `<strong>${v}</strong>` },
      {
        key: 'records', label: 'DNS Records',
        render: (v) => {
          if (!v?.length) return '<span class="muted">—</span>';
          const types = [...new Set(v.map(r => r.type))];
          return types.map(t => `<span class="dns-badge">${t}</span>`).join(' ');
        },
        searchable: false,
      },
      {
        key: 'ips', label: 'Resolved IPs',
        render: (v) => {
          if (!v?.length) return '<span class="muted">—</span>';
          return v.map(ip => `<span class="mono small">${ip}</span>`).join('<br>');
        },
        searchable: false,
      },
      {
        key: 'subdomains', label: 'Subdomains',
        render: (v) => {
          if (!v?.length) return '<span class="muted">0</span>';
          return `<span class="count-badge">${v.length}</span>`;
        },
        sortable: false, searchable: false,
      },
      {
        key: 'registrar', label: 'Registrar',
        render: v => v || '<span class="muted">—</span>',
      },
      {
        key: 'expires', label: 'Expires',
        render: (v) => {
          if (!v) return '<span class="muted">—</span>';
          const d = new Date(v);
          const days = Math.floor((d - Date.now()) / 86400000);
          const str = d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
          if (days < 0) return `<span class="text-danger">${str} (expired)</span>`;
          if (days < 30) return `<span class="text-warning">${str}</span>`;
          return str;
        },
      },
      {
        key: 'source', label: 'Source',
        render: v => `<span class="source-badge src-${v}">${v}</span>`,
        sortable: false,
      },
    ],
    onRowClick: entity => onSelect?.(entity),
    emptyMessage: 'No domains found. Load data or adjust filters.',
  });

  table.addFilter('source', 'All Sources', [
    { value: 'dns-recon', label: 'DNS Recon' },
    { value: 'mock', label: 'Demo' },
  ]);

  container.appendChild(table.el);

  function refresh() {
    table.setData(store.getAll(EntityType.DOMAIN));
  }

  store.addEventListener('change:domain', refresh);
  refresh();

  return () => store.removeEventListener('change:domain', refresh);
}
