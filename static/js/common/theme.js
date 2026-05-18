// Theme toggle — persists 'dark' | 'light' in localStorage.

(function () {
  const KEY = "dojaa-theme";
  const root = document.documentElement;

  function apply(theme) {
    root.setAttribute("data-theme", theme);
    document.querySelectorAll(".theme-icon-dark").forEach((el) => {
      el.style.display = theme === "dark" ? "" : "none";
    });
    document.querySelectorAll(".theme-icon-light").forEach((el) => {
      el.style.display = theme === "light" ? "" : "none";
    });
  }

  // Initial theme — read before DOMContentLoaded to avoid FOUC on the icon swap.
  const saved = (function () {
    try { return localStorage.getItem(KEY); } catch (e) { return null; }
  })();
  apply(saved === "light" ? "light" : "dark");

  document.addEventListener("DOMContentLoaded", () => {
    apply(root.getAttribute("data-theme") || "dark");
    document.querySelectorAll("[data-theme-toggle]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
        apply(next);
        try { localStorage.setItem(KEY, next); } catch (e) { /* noop */ }
        if (window.dojaaCharts && typeof window.dojaaCharts.refreshAll === "function") {
          window.dojaaCharts.refreshAll();
        }
      });
    });
  });
})();
