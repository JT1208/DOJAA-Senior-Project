// Certificates view: TLS/SSL metadata including validity, issuers, SANs, and expiry status.
// Only certificate-type entities appear here. No vulnerability or host data leaks into this view.

import { EntityType } from '../schema.js';
import { DataTable } from '../ui/table.js';

export function mount(container, store, { onSelect } = {}) {
  container.innerHTML = '';

  const header = document.createElement('div');
  header.className = 'view-header';
  header.innerHTML = '<h2>Certificates <span class="view-desc">TLS/SSL certificate metadata, validity status, and domain relationships</span></h2>';
  container.appendChild(header);

  const table = new DataTable({
    columns: [
      {
        key: 'subject', label: 'Subject',
        render: (v, item) => {
          let badge = '';
          if (item.isExpired) badge = '<span class="cert-status-badge cert-expired">EXPIRED</span>';
          else if (item.daysUntilExpiry != null && item.daysUntilExpiry <= 30)
            badge = `<span class="cert-status-badge cert-expiring">EXPIRING ${item.daysUntilExpiry}d</span>`;
          return `${badge}<strong>${v}</strong>`;
        },
      },
      {
        key: 'issuer', label: 'Issuer',
        render: v => {
          const isSelfsigned = v?.toLowerCase().includes('self');
          return isSelfsigned ? `<span class="text-warning">${v}</span>` : (v || '—');
        },
      },
      {
        key: 'domains', label: 'Domains (SANs)',
        render: (v) => {
          if (!v?.length) return '<span class="muted">—</span>';
          return v.slice(0, 2).map(d => `<span class="san-tag">${d}</span>`).join(' ') +
            (v.length > 2 ? `<span class="muted"> +${v.length - 2}</span>` : '');
        },
        searchable: false,
      },
      {
        key: 'validFrom', label: 'Valid From',
        render: v => v ? new Date(v).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }) : '—',
      },
      {
        key: 'validTo', label: 'Valid To',
        render: (v, item) => {
          if (!v) return '—';
          const str = new Date(v).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
          if (item.isExpired) return `<span class="text-danger">${str}</span>`;
          if (item.daysUntilExpiry != null && item.daysUntilExpiry <= 30)
            return `<span class="text-warning">${str}</span>`;
          return str;
        },
      },
      {
        key: 'algorithm', label: 'Algorithm',
        render: v => v || '<span class="muted">—</span>',
      },
      {
        key: 'source', label: 'Source',
        render: v => `<span class="source-badge src-${v}">${v}</span>`,
        sortable: false,
      },
    ],
    onRowClick: entity => onSelect?.(entity),
    emptyMessage: 'No certificates found. Load data or adjust filters.',
  });

  table.addFilter('_status', 'All Statuses', [
    { value: 'valid', label: 'Valid' },
    { value: 'expiring', label: 'Expiring Soon (≤30d)' },
    { value: 'expired', label: 'Expired' },
  ]);
  table.addFilter('issuer', 'All Issuers', [
    { value: "Let's Encrypt", label: "Let's Encrypt" },
    { value: 'DigiCert Inc', label: 'DigiCert' },
    { value: 'Sectigo Limited', label: 'Sectigo' },
    { value: 'Self-signed', label: 'Self-signed' },
  ]);

  container.appendChild(table.el);

  function refresh() {
    // Attach a computed _status field for the filter to work on
    const data = store.getAll(EntityType.CERTIFICATE).map(c => ({
      ...c,
      _status: c.isExpired ? 'expired'
        : (c.daysUntilExpiry != null && c.daysUntilExpiry <= 30 ? 'expiring' : 'valid'),
    }));
    table.setData(data);
  }

  store.addEventListener('change:certificate', refresh);
  refresh();

  return () => store.removeEventListener('change:certificate', refresh);
}
