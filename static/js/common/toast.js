// Tiny toast notification system.
// Usage: dojaaToast.show({ title, body, type: 'success'|'error'|'info', timeout: 4000 });

(function (global) {
  function ensureStack() {
    let stack = document.querySelector("[data-toast-stack]");
    if (!stack) {
      stack = document.createElement("div");
      stack.className = "toast-stack";
      stack.setAttribute("data-toast-stack", "");
      document.body.appendChild(stack);
    }
    return stack;
  }

  const ICONS = {
    success: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
    error:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
    info:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
  };

  function show(opts) {
    const { title = "", body = "", type = "info", timeout = 4200 } = opts || {};
    const stack = ensureStack();
    const el = document.createElement("div");
    el.className = `toast toast--${type}`;
    el.setAttribute("role", type === "error" ? "alert" : "status");
    el.innerHTML =
      `<div class="toast__icon">${ICONS[type] || ICONS.info}</div>` +
      `<div class="toast__body">${title ? `<div class="toast__title"></div>` : ""}<div class="toast__msg"></div></div>`;
    if (title) el.querySelector(".toast__title").textContent = title;
    el.querySelector(".toast__msg").textContent = body || title;
    stack.appendChild(el);
    if (timeout > 0) {
      setTimeout(() => {
        el.style.transition = "opacity .2s, transform .2s";
        el.style.opacity = "0";
        el.style.transform = "translateX(12px)";
        setTimeout(() => el.remove(), 240);
      }, timeout);
    }
    return el;
  }

  global.dojaaToast = { show };
})(window);
