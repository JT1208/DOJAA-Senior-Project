// Lightweight nav helpers — dropdown toggle + active-link highlighting.

(function () {
  document.addEventListener("DOMContentLoaded", function () {
    // Active link
    const here = window.location.pathname.replace(/\/+$/, "") || "/";
    document.querySelectorAll(".app-nav__links a[data-path]").forEach((a) => {
      const path = a.getAttribute("data-path");
      if (here === path || here.startsWith(path + "/")) a.classList.add("is-active");
    });

    // Dropdown toggle
    document.querySelectorAll("[data-dropdown]").forEach((root) => {
      const btn = root.querySelector(".app-nav__dropdown-btn");
      if (!btn) return;
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const wasOpen = root.classList.contains("is-open");
        document.querySelectorAll("[data-dropdown].is-open").forEach((d) => d.classList.remove("is-open"));
        if (!wasOpen) root.classList.add("is-open");
      });
    });
    document.addEventListener("click", () => {
      document.querySelectorAll("[data-dropdown].is-open").forEach((d) => d.classList.remove("is-open"));
    });

    // Flash dismiss
    document.querySelectorAll(".alert__close").forEach((btn) => {
      btn.addEventListener("click", () => btn.closest(".alert")?.remove());
    });
  });
})();
