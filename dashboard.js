// ---------------------------------------------------------------------------
// EmailJS: Get keys at https://dashboard.emailjs.com/
// Template variables: {{to_email}}, {{subject}}, {{message}}, {{from_name}}
// ---------------------------------------------------------------------------
const EMAILJS_CONFIG = {
  publicKey: 'YOUR_PUBLIC_KEY',
  serviceId: 'YOUR_SERVICE_ID',
  templateId: 'YOUR_TEMPLATE_ID',
};

const isEmailJSConfigured = () =>
  EMAILJS_CONFIG.publicKey && EMAILJS_CONFIG.publicKey !== 'YOUR_PUBLIC_KEY' &&
  EMAILJS_CONFIG.serviceId && EMAILJS_CONFIG.serviceId !== 'YOUR_SERVICE_ID' &&
  EMAILJS_CONFIG.templateId && EMAILJS_CONFIG.templateId !== 'YOUR_TEMPLATE_ID';

// Auth check and show user
if (!sessionStorage.getItem('dojaa_authenticated')) {
  window.location.href = 'login.html';
} else {
  document.getElementById('user-email').textContent = sessionStorage.getItem('dojaa_user') || '';
}

// Alert icon: show when something is detected (set by your scan/detection logic)
function updateAlertIconVisibility() {
  const headerAlert = document.getElementById('header-alert');
  const hasAlerts = sessionStorage.getItem('dojaa_has_alerts') === 'true' || window.dojaaDetectedAlerts;
  if (headerAlert) {
    headerAlert.classList.toggle('has-alert', !!hasAlerts);
    headerAlert.setAttribute('aria-hidden', !hasAlerts);
  }
}

// Demo: show alert icon. When your scan/detection finds something, set: sessionStorage.setItem('dojaa_has_alerts', 'true')
if (sessionStorage.getItem('dojaa_has_alerts') === null) {
  sessionStorage.setItem('dojaa_has_alerts', 'true');
}
updateAlertIconVisibility();

// Dropdown: open/close when clicking alert icon or outside
const alertIconBtn = document.getElementById('alert-icon-btn');
const alertDropdown = document.getElementById('alert-dropdown');

if (alertIconBtn && alertDropdown) {
  alertIconBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    const isOpen = alertDropdown.classList.toggle('is-open');
    if (isOpen) {
      const toInput = document.getElementById('alert-to');
      if (toInput && !toInput.value) {
        toInput.value = sessionStorage.getItem('dojaa_user') || '';
      }
    }
  });

  document.addEventListener('click', () => {
    alertDropdown.classList.remove('is-open');
  });
  alertDropdown.addEventListener('click', (e) => e.stopPropagation());
}

function initEmailJS() {
  if (typeof emailjs === 'undefined') return;
  if (isEmailJSConfigured()) {
    emailjs.init(EMAILJS_CONFIG.publicKey);
  }
}

// Alert form: send email via EmailJS or fallback to mailto
const alertForm = document.getElementById('alert-form');
const alertTo = document.getElementById('alert-to');
const alertSubject = document.getElementById('alert-subject');
const alertMessage = document.getElementById('alert-message');
const alertSubmit = document.getElementById('alert-submit');
const alertStatus = document.getElementById('alert-status');
const alertToError = document.getElementById('alert-to-error');

function setStatus(text, type) {
  if (!alertStatus) return;
  alertStatus.textContent = text;
  alertStatus.className = 'alert-status' + (type ? ' ' + type : '');
}

function clearAlertToError() {
  if (alertToError) {
    alertToError.textContent = '';
    alertToError.classList.remove('visible');
  }
  if (alertTo) alertTo.classList.remove('invalid');
}

if (alertForm) {
  alertForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearAlertToError();
    setStatus('');

    const to = alertTo.value.trim();
    const subject = alertSubject.value.trim();
    const message = alertMessage.value.trim();

    if (!to) {
      if (alertToError) {
        alertToError.textContent = 'Enter a recipient email.';
        alertToError.classList.add('visible');
      }
      if (alertTo) alertTo.classList.add('invalid');
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) {
      if (alertToError) {
        alertToError.textContent = 'Enter a valid email address.';
        alertToError.classList.add('visible');
      }
      if (alertTo) alertTo.classList.add('invalid');
      return;
    }
    if (!subject) {
      setStatus('Please enter a subject.', 'error');
      return;
    }
    if (!message) {
      setStatus('Please enter a message.', 'error');
      return;
    }

    const fromName = sessionStorage.getItem('dojaa_user') || 'DOJAA Dashboard';

    if (isEmailJSConfigured() && typeof emailjs !== 'undefined') {
      alertSubmit.disabled = true;
      setStatus('Sending…');

      const templateParams = {
        to_email: to,
        subject: subject,
        message: message,
        from_name: fromName,
      };

      try {
        await emailjs.send(
          EMAILJS_CONFIG.serviceId,
          EMAILJS_CONFIG.templateId,
          templateParams
        );
        setStatus('Alert sent.', 'success');
        alertForm.reset();
        if (alertTo) alertTo.value = sessionStorage.getItem('dojaa_user') || '';
      } catch (err) {
        console.error('EmailJS error:', err);
        setStatus('Send failed. Check EmailJS config.', 'error');
      } finally {
        alertSubmit.disabled = false;
      }
    } else {
      const mailto = 'mailto:' + encodeURIComponent(to) +
        '?subject=' + encodeURIComponent(subject) +
        '&body=' + encodeURIComponent(message + '\n\n— DOJAA Dashboard, ' + fromName);
      window.location.href = mailto;
      setStatus('Opened mail client.', 'success');
    }
  });

  if (alertTo) alertTo.addEventListener('input', clearAlertToError);
}

function initDashboardFilters() {
  const dataTypeSelect = document.getElementById('data-type-select');
  const dataDetailsList = document.querySelector('.panel-data-details ul');

  if (!dataTypeSelect || !dataDetailsList) return;

  const items = Array.from(dataDetailsList.querySelectorAll('li'));

  const updateVisibility = () => {
    const selected = dataTypeSelect.value;

    if (!selected) {
      items.forEach((item) => {
        item.classList.remove('is-hidden');
      });
      return;
    }

    items.forEach((item) => {
      const type = item.getAttribute('data-type');
      if (type === selected) {
        item.classList.remove('is-hidden');
      } else {
        item.classList.add('is-hidden');
      }
    });
  };

  dataTypeSelect.addEventListener('change', updateVisibility);
  updateVisibility();
}

function initExposureScore() {
  const circle = document.getElementById('exposure-score-circle');
  const valueEl = document.getElementById('exposure-score-value');

  if (!circle || !valueEl) return;

  let score = Number(sessionStorage.getItem('dojaa_exposure_score'));
  if (!Number.isFinite(score)) {
    score = 72;
  }

  // Clamp between 0–100
  score = Math.max(0, Math.min(100, score));
  valueEl.textContent = score;

  // Map 0–100 to a conic gradient sweep angle
  const angle = (score / 100) * 360;
  circle.style.setProperty('--exposure-angle', angle.toFixed(0) + 'deg');
}

function parseCsvLine(line) {
  const result = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];

    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === ',' && !inQuotes) {
      result.push(current);
      current = '';
    } else {
      current += ch;
    }
  }

  result.push(current);

  return result.map((field) => {
    let trimmed = field.trim();
    if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
      trimmed = trimmed.slice(1, -1).replace(/""/g, '"');
    }
    return trimmed;
  });
}

function parseCsv(text) {
  if (!text) return [];

  const lines = text.split(/\r?\n/).filter((line) => line.trim() !== '');
  if (lines.length <= 1) return [];

  const headers = parseCsvLine(lines[0]).map((h) => h.trim());
  const rows = [];

  for (let i = 1; i < lines.length; i++) {
    const fields = parseCsvLine(lines[i]);
    if (!fields.length) continue;

    const row = {};
    headers.forEach((header, idx) => {
      row[header] = fields[idx] != null ? fields[idx] : '';
    });
    rows.push(row);
  }

  return rows;
}

function normalizeSeverityLabel(value) {
  const s = String(value || '').toLowerCase();
  if (s.startsWith('crit')) return 'critical';
  if (s.startsWith('hi')) return 'high';
  if (s.startsWith('med')) return 'medium';
  if (s.startsWith('lo')) return 'low';
  return '';
}

function getSeverityBucket(row) {
  const severityRaw =
    row.severity ?? row.SEVERITY ?? row.Severity ?? row.severity_label ?? row.SEVERITY_LABEL;

  if (severityRaw != null && severityRaw !== '') {
    const bucket = normalizeSeverityLabel(severityRaw);
    if (bucket) return bucket;
  }

  const scoreRaw =
    row.severity_score ?? row.SEVERITY_SCORE ?? row.cvss_score ?? row.CVSS_SCORE ?? row.score ?? row.SCORE;
  const score = typeof scoreRaw === 'number' ? scoreRaw : parseFloat(String(scoreRaw || ''));

  if (!Number.isFinite(score)) return 'low';

  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  return 'low';
}

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function updateRiskList(rows) {
  const listEl = document.getElementById('risk-list');
  const subtitleEl = document.querySelector('.risk-list-subtitle');

  if (!listEl) return;

  listEl.innerHTML = '';

  if (!rows.length) {
    if (subtitleEl) subtitleEl.textContent = 'Upload a CVE CSV to display risks by severity.';
    return;
  }

  const enriched = rows.map((row) => ({ ...row, _bucket: getSeverityBucket(row) }));
  enriched.sort((a, b) => SEVERITY_ORDER[a._bucket] - SEVERITY_ORDER[b._bucket]);

  if (subtitleEl) subtitleEl.textContent = `${rows.length} CVEs by severity`;

  enriched.forEach((row) => {
    const id = row.id ?? row.ID ?? row.cve_id ?? row.CVE_ID ?? '—';
    const summary = row.summary ?? row.SUMMARY ?? row.description ?? row.DESCRIPTION ?? '';

    const li = document.createElement('li');
    li.innerHTML =
      '<span class="risk-severity-badge ' + row._bucket + '" aria-hidden="true"></span>' +
      '<span class="risk-content">' +
      '<span class="risk-id">' + escapeHtml(String(id)) + '</span> ' +
      '<span class="risk-summary">' + escapeHtml(String(summary)) + '</span>' +
      '</span>';
    listEl.appendChild(li);
  });
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function deriveSeverityCounts(rows) {
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  rows.forEach((row) => {
    let severityRaw =
      row.severity ??
      row.SEVERITY ??
      row.Severity ??
      row.severity_label ??
      row.SEVERITY_LABEL;

    if (severityRaw != null && severityRaw !== '') {
      const bucket = normalizeSeverityLabel(severityRaw);
      if (bucket && Object.prototype.hasOwnProperty.call(counts, bucket)) {
        counts[bucket]++;
        return;
      }
    }

    const scoreRaw =
      row.severity_score ??
      row.SEVERITY_SCORE ??
      row.cvss_score ??
      row.CVSS_SCORE ??
      row.score ??
      row.SCORE;

    const score =
      typeof scoreRaw === 'number' ? scoreRaw : parseFloat(String(scoreRaw || ''));

    if (!Number.isFinite(score)) return;

    let bucket;
    if (score >= 9.0) bucket = 'critical';
    else if (score >= 7.0) bucket = 'high';
    else if (score >= 4.0) bucket = 'medium';
    else bucket = 'low';

    counts[bucket]++;
  });

  return counts;
}

function updateSeverityPieFromCounts(pieEl, counts) {
  const total =
    counts.critical + counts.high + counts.medium + counts.low;

  if (!pieEl || !total) return;

  const criticalAngle = (counts.critical / total) * 360;
  const highAngle = (counts.high / total) * 360;
  const mediumAngle = (counts.medium / total) * 360;

  const criticalEnd = criticalAngle;
  const highEnd = criticalEnd + highAngle;
  const mediumEnd = highEnd + mediumAngle;
  const lowEnd = 360;

  pieEl.style.background =
    'radial-gradient(farthest-side, rgba(15, 23, 42, 0.12) 58%, transparent 60%),' +
    'conic-gradient(' +
    '#ef4444 0deg ' + criticalEnd + 'deg,' +
    '#f97316 ' + criticalEnd + 'deg ' + highEnd + 'deg,' +
    '#eab308 ' + highEnd + 'deg ' + mediumEnd + 'deg,' +
    '#22c55e ' + mediumEnd + 'deg ' + lowEnd + 'deg' +
    ')';

  const percentages = {
    critical: (counts.critical / total) * 100,
    high: (counts.high / total) * 100,
    medium: (counts.medium / total) * 100,
    low: (counts.low / total) * 100,
  };

  const label =
    'Distribution of vulnerabilities by severity: ' +
    'Critical ' + Math.round(percentages.critical) + ' percent, ' +
    'High ' + Math.round(percentages.high) + ' percent, ' +
    'Medium ' + Math.round(percentages.medium) + ' percent, ' +
    'Low ' + Math.round(percentages.low) + ' percent.';

  pieEl.setAttribute('aria-label', label);
}

function initSeverityDistribution() {
  const fileInput = document.getElementById('cve-csv-input');
  const pieEl = document.querySelector('.severity-pie');

  if (!fileInput || !pieEl) return;

  const handleCsvText = (text) => {
    const rows = parseCsv(text);
    if (!rows.length) return;

    const counts = deriveSeverityCounts(rows);
    updateSeverityPieFromCounts(pieEl, counts);
    updateRiskList(rows);
  };

  fileInput.addEventListener('change', (event) => {
    const input = event.target;
    if (!input.files || !input.files[0]) return;

    const file = input.files[0];
    const reader = new FileReader();

    reader.onload = () => {
      try {
        handleCsvText(String(reader.result || ''));
      } catch (err) {
        console.error('Failed to parse CVE CSV:', err);
      }
    };

    reader.readAsText(file);
  });
}

function init() {
  initEmailJS();
  initDashboardFilters();
  initExposureScore();
  initSeverityDistribution();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
