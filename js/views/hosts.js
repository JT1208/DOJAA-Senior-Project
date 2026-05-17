// Hosts view: IP addresses, open ports, services, OS, geolocation, and exposure metadata.
// Only host-type entities are displayed here. No vulnerability or domain data leaks into this view.

import { EntityType } from '../schema.js';
import { DataTable } from '../ui/table.js';

export function mount(container, store, { onSelect } = {}) {
  container.innerHTML = '';

  const header = document.createElement('div');
  header.className = 'view-header';
  header.innerHTML = '<h2>Hosts <span class="view-desc">Infrastructure exposure: IP addresses, open ports, and running services</span></h2>';
  container.appendChild(header);

  const table = new DataTable({
    columns: [
      {
        key: 'ip', label: 'IP Address',
        render: v => `<span class="mono">${v}</span>`,
      },
      {
        key: 'hostname', label: 'Hostname',
        render: v => v || '<span class="muted">—</span>',
      },
      {
        key: 'ports', label: 'Ports',
        render: (v) => {
          if (!v?.length) return '<span class="muted">—</span>';
          const shown = v.slice(0, 5).map(p => `<span class="port-badge">${p.port}/${p.protocol}</span>`).join('');
          const more = v.length > 5 ? `<span class="muted">+${v.length - 5}</span>` : '';
          return shown + more;
        },
        searchable: false,
      },
      {
        key: 'services', label: 'Services',
        render: (v) => {
          if (!v?.length) return '<span class="muted">—</span>';
          return v.slice(0, 2).map(s => {
            const name = [s.product, s.version].filter(Boolean).join(' ') || s.name;
            return `<span class="svc-tag">${name}</span>`;
          }).join(' ');
        },
        searchable: false,
      },
      { key: 'os', label: 'OS', render: v => v || '<span class="muted">—</span>' },
      { key: 'country', label: 'Country', render: v => v || '<span class="muted">—</span>' },
      {
        key: 'lastSeen', label: 'Last Seen',
        render: v => v ? new Date(v).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : '—',
      },
      {
        key: 'source', label: 'Source',
        render: v => `<span class="source-badge src-${v}">${v}</span>`,
        sortable: false,
      },
    ],
    onRowClick: entity => onSelect?.(entity),
    emptyMessage: 'No hosts found. Load data or adjust filters.',
  });

  table.addFilter('country', 'All Countries', [
    { value: 'US', label: 'United States' },
    { value: 'DE', label: 'Germany' },
    { value: 'CN', label: 'China' },
    { value: 'RU', label: 'Russia' },
  ]);
  table.addFilter('source', 'All Sources', [
    { value: 'shodan', label: 'Shodan' },
    { value: 'censys', label: 'Censys' },
    { value: 'mock', label: 'Demo' },
  ]);

  container.appendChild(table.el);

  function refresh() {
    table.setData(store.getAll(EntityType.HOST));
  }

  store.addEventListener('change:host', refresh);
  refresh();

  return () => store.removeEventListener('change:host', refresh);
}
