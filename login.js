const ALLOWED_EMAILS = [
  'ogs23@drexel.edu',
  'do427@drexel.edu',
  'aw3542@drexel.edu',
  'ayb32@drexel.edu',
  'jt3327@drexel.edu'
];
const DEFAULT_PASSWORD = 'Drexel123!';

const form = document.getElementById('login-form');
const emailInput = document.getElementById('email');
const passwordInput = document.getElementById('password');
const emailError = document.getElementById('email-error');
const passwordError = document.getElementById('password-error');

function showError(input, message) {
  input.classList.add('invalid');
  const errorEl = input.id === 'email' ? emailError : passwordError;
  errorEl.textContent = message;
  errorEl.classList.add('visible');
}

function clearError(input) {
  input.classList.remove('invalid');
  const errorEl = input.id === 'email' ? emailError : passwordError;
  errorEl.classList.remove('visible');
}

form.addEventListener('submit', (e) => {
  e.preventDefault();
  let valid = true;

  clearError(emailInput);
  clearError(passwordInput);

  const email = emailInput.value.trim().toLowerCase();
  const password = passwordInput.value;

  if (!email) {
    showError(emailInput, 'Please enter your email address.');
    valid = false;
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    showError(emailInput, 'Please enter a valid email address.');
    valid = false;
  } else if (!ALLOWED_EMAILS.includes(email)) {
    showError(emailInput, 'This email is not authorized to access the dashboard.');
    valid = false;
  }

  if (!password) {
    showError(passwordInput, 'Please enter your password.');
    valid = false;
  } else if (password !== DEFAULT_PASSWORD) {
    showError(passwordInput, 'Invalid password.');
    valid = false;
  }

  if (valid) {
    sessionStorage.setItem('dojaa_user', email);
    sessionStorage.setItem('dojaa_authenticated', 'true');
    window.location.href = 'dashboard.html';
  }
});

emailInput.addEventListener('input', () => clearError(emailInput));
passwordInput.addEventListener('input', () => clearError(passwordInput));
