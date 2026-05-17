// Main entry point: auth check, data bootstrap, tab management, and summary bar.
// Orchestrates: store → mock data → correlations → views → detail panel.

import { store } from './store.js';
import { EntityType, SEVERITY_COLOR } from './schema.js';
import { buildCorrelations } from './correlations.js';
import { mockHosts, mockDomains, mockVulnerabilities, mockCertificates, mockThreats } from './adapters/mock.js';
import { DetailPanel } from './ui/detail.js';
import { mount as mountHosts } from './views/hosts.js';
import { mount as mountDomains } from './views/domains.js';
import { mount as mountVulnerabilities } from './views/vulnerabilities.js';
import { mount as mountCertificates } from './views/certificates.js';
import { mount as mountIntelligence } from './views/intelligence.js';

// ---------------------------------------------------------------------------
// Auth check
// ---------------------------------------------------------------------------
if (!sessionStorage.getItem('dojaa_authenticated')) {
  window.location.href = 'login.html';
}

const userEl = document.getElementById('user-email');
if (userEl) userEl.textContent = sessionStorage.getItem('dojaa_user') || '';

// ---------------------------------------------------------------------------
// Bootstrap data
// ---------------------------------------------------------------------------
store.load(EntityType.HOST, mockHosts);
store.load(EntityType.DOMAIN, mockDomains);
store.load(EntityType.VULNERABILITY, mockVulnerabilities);
store.load(EntityType.CERTIFICATE, mockCertificates);
store.load(EntityType.THREAT, mockThreats);
store.setCorrelations(buildCorrelations(store));

// ---------------------------------------------------------------------------
// Detail panel (shared singleton)
// ---------------------------------------------------------------------------
const detail = new DetailPanel(store);
document.body.appendChild(detail.el);

function handleSelect(entity) {
  detail.show(entity);
}

// ---------------------------------------------------------------------------
// Summary bar
// ---------------------------------------------------------------------------
function renderSummary() {
  const bar = document.getElementById('summary-bar');
  if (!bar) return;
  const s = store.getSummary();
  const sev = s.severityCounts;

  bar.innerHTML = `
    <div class="sum-card sum-risk" title="Composite risk score based on vulnerability severity and active threats">
      <div class="sum-val risk-score-val" style="color:${riskColor(s.riskScore)}">${s.riskScore}</div>
      <div class="sum-lbl">Risk Score</div>
    </div>
    <div class="sum-card" data-nav="hosts" title="Click to view hosts">
      <div class="sum-val">${s.hosts}</div>
      <div class="sum-lbl">Hosts</div>
    </div>
    <div class="sum-card sum-split" title="Vulnerability severity breakdown">
      <div class="sum-sev-row">
        <span class="sev-chip sev-critical">${sev.critical}<em>C</em></span>
        <span class="sev-chip sev-high">${sev.high}<em>H</em></span>
        <span class="sev-chip sev-medium">${sev.medium}<em>M</em></span>
        <span class="sev-chip sev-low">${sev.low}<em>L</em></span>
      </div>
      <div class="sum-lbl" data-nav="vulnerabilities" style="cursor:pointer">${s.vulnerabilities} Vulnerabilities</div>
    </div>
    <div class="sum-card ${s.expiredCerts + s.expiringSoon > 0 ? 'sum-warn' : ''}" data-nav="certificates" title="Click to view certificates">
      <div class="sum-val">${s.certificates}</div>
      <div class="sum-lbl">Certs${s.expiredCerts > 0 ? ` · <span class="text-danger">${s.expiredCerts} expired</span>` : ''}${s.expiringSoon > 0 ? ` · <span class="text-warning">${s.expiringSoon} expiring</span>` : ''}</div>
    </div>
    <div class="sum-card ${s.activeThreats > 0 ? 'sum-alert' : ''}" data-nav="intelligence" title="Click to view threat intelligence">
      <div class="sum-val">${s.threats}</div>
      <div class="sum-lbl">Threats${s.activeThreats > 0 ? ` · <span class="text-danger">${s.activeThreats} critical/high</span>` : ''}</div>
    </div>
  `;

  // Nav clicks on summary cards
  bar.querySelectorAll('[data-nav]').forEach(el => {
    el.addEventListener('click', () => switchTab(el.dataset.nav));
  });
}

function riskColor(score) {
  if (score >= 75) return SEVERITY_COLOR.critical;
  if (score >= 50) return SEVERITY_COLOR.high;
  if (score >= 25) return SEVERITY_COLOR.medium;
  return SEVERITY_COLOR.low;
}

store.addEventListener('change', renderSummary);
renderSummary();

// ---------------------------------------------------------------------------
// Tab management
// ---------------------------------------------------------------------------
const VIEWS = {
  hosts: mountHosts,
  domains: mountDomains,
  vulnerabilities: mountVulnerabilities,
  certificates: mountCertificates,
  intelligence: mountIntelligence,
};

let activeTab = null;
let unmountCurrent = null;

function switchTab(tabName) {
  if (activeTab === tabName) return;

  // Update nav buttons
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.toggle('tab-btn-active', btn.dataset.tab === tabName);
  });

  // Hide/show panels
  document.querySelectorAll('.tab-panel').forEach(panel => {
    panel.classList.toggle('hidden', panel.dataset.tab !== tabName);
  });

  // Unmount previous view
  if (unmountCurrent) { unmountCurrent(); unmountCurrent = null; }

  // Close detail panel when switching tabs
  detail.hide();

  // Mount new view
  const panel = document.querySelector(`.tab-panel[data-tab="${tabName}"]`);
  if (panel && VIEWS[tabName]) {
    unmountCurrent = VIEWS[tabName](panel, store, { onSelect: handleSelect }) || null;
  }

  activeTab = tabName;
}

// Wire up nav buttons
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => switchTab(btn.dataset.tab));
});

// Initial tab
switchTab('hosts');

// ---------------------------------------------------------------------------
// Alert / Email functionality (preserved from original)
// ---------------------------------------------------------------------------
const EMAILJS_CONFIG = {
  publicKey: 'YOUR_PUBLIC_KEY',
  serviceId: 'YOUR_SERVICE_ID',
  templateId: 'YOUR_TEMPLATE_ID',
};
const emailJsConfigured = () =>
  EMAILJS_CONFIG.publicKey !== 'YOUR_PUBLIC_KEY' &&
  EMAILJS_CONFIG.serviceId !== 'YOUR_SERVICE_ID' &&
  EMAILJS_CONFIG.templateId !== 'YOUR_TEMPLATE_ID';

// Show alert icon when high/critical threats exist
function updateAlertIcon() {
  const alertEl = document.getElementById('header-alert');
  if (!alertEl) return;
  const s = store.getSummary();
  const hasAlerts = s.activeThreats > 0;
  alertEl.classList.toggle('has-alert', hasAlerts);
  alertEl.setAttribute('aria-hidden', String(!hasAlerts));
  const badge = document.getElementById('alert-badge');
  if (badge) badge.textContent = String(s.activeThreats);
}

store.addEventListener('change', updateAlertIcon);
updateAlertIcon();

const alertBtn = document.getElementById('alert-icon-btn');
const alertDropdown = document.getElementById('alert-dropdown');
if (alertBtn && alertDropdown) {
  alertBtn.addEventListener('click', e => {
    e.stopPropagation();
    const open = alertDropdown.classList.toggle('is-open');
    if (open) {
      const toInput = document.getElementById('alert-to');
      if (toInput && !toInput.value) toInput.value = sessionStorage.getItem('dojaa_user') || '';
    }
  });
  document.addEventListener('click', () => alertDropdown.classList.remove('is-open'));
  alertDropdown.addEventListener('click', e => e.stopPropagation());
}

const alertForm = document.getElementById('alert-form');
if (alertForm) {
  alertForm.addEventListener('submit', async e => {
    e.preventDefault();
    const to = document.getElementById('alert-to')?.value.trim();
    const subject = document.getElementById('alert-subject')?.value.trim();
    const message = document.getElementById('alert-message')?.value.trim();
    const statusEl = document.getElementById('alert-status');
    const toError = document.getElementById('alert-to-error');

    if (!to || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) {
      if (toError) { toError.textContent = 'Enter a valid email.'; toError.classList.add('visible'); }
      return;
    }
    if (!subject || !message) {
      if (statusEl) { statusEl.textContent = 'Subject and message required.'; statusEl.className = 'alert-status error'; }
      return;
    }

    if (emailJsConfigured() && typeof emailjs !== 'undefined') {
      const submitBtn = document.getElementById('alert-submit');
      if (submitBtn) submitBtn.disabled = true;
      if (statusEl) statusEl.textContent = 'Sending…';
      try {
        await emailjs.send(EMAILJS_CONFIG.serviceId, EMAILJS_CONFIG.templateId, {
          to_email: to, subject, message, from_name: sessionStorage.getItem('dojaa_user') || 'DOJAA',
        });
        if (statusEl) { statusEl.textContent = 'Alert sent.'; statusEl.className = 'alert-status success'; }
        alertForm.reset();
      } catch {
        if (statusEl) { statusEl.textContent = 'Send failed. Check EmailJS config.'; statusEl.className = 'alert-status error'; }
      } finally {
        if (submitBtn) submitBtn.disabled = false;
      }
    } else {
      window.location.href = `mailto:${encodeURIComponent(to)}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(message)}`;
      if (statusEl) { statusEl.textContent = 'Opened mail client.'; statusEl.className = 'alert-status success'; }
    }
  });
}

// Rescan: reload mock data and rebuild correlations (demo stub)
document.getElementById('header-rescan-btn')?.addEventListener('click', () => {
  store.load(EntityType.HOST, mockHosts);
  store.load(EntityType.DOMAIN, mockDomains);
  store.load(EntityType.VULNERABILITY, mockVulnerabilities);
  store.load(EntityType.CERTIFICATE, mockCertificates);
  store.load(EntityType.THREAT, mockThreats);
  store.setCorrelations(buildCorrelations(store));
  // Re-render active view
  const current = activeTab;
  activeTab = null;
  switchTab(current);
});

// Report: opens print dialog (stub — replace with PDF generation)
document.getElementById('header-report-btn')?.addEventListener('click', () => {
  window.print();
});
