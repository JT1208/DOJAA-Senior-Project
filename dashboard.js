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

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initEmailJS);
} else {
  initEmailJS();
}
