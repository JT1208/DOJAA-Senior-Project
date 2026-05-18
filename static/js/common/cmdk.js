// Command palette — Cmd/Ctrl+K to open, keyboard nav, fuzzy filter.

(function (global) {
  const ICONS = {
    page: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>',
    tool: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a4 4 0 0 0-5.66 5.66l-7.04 7.04L5.83 22l7.04-7.04A4 4 0 0 0 18.53 9.3"/></svg>',
    cmd:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>',
  };

  const ITEMS = [
    { group: "Pages", icon: "page", label: "Dashboard",      hint: "G D", path: "/dashboard" },
    { group: "Pages", icon: "page", label: "Hosts",          hint: "G H", path: "/hosts" },
    { group: "Pages", icon: "page", label: "Ports",          hint: "G P", path: "/ports" },
    { group: "Pages", icon: "page", label: "Risk",           hint: "G R", path: "/risk" },
    { group: "Pages", icon: "page", label: "CVEs",           hint: "G C", path: "/cves" },
    { group: "Pages", icon: "page", label: "SSL/TLS",        hint: "G S", path: "/ssl-tls" },
    { group: "Pages", icon: "page", label: "Graph",          hint: "G G", path: "/graph" },
    { group: "Tools", icon: "tool", label: "DNS lookup",                  path: "/tools/dns" },
    { group: "Tools", icon: "tool", label: "Security headers",            path: "/tools/headers" },
    { group: "Tools", icon: "tool", label: "Robots.txt",                  path: "/tools/robots" },
    { group: "Actions", icon: "cmd", label: "Download PDF report",        path: "/reports/dashboard.pdf" },
    { group: "Actions", icon: "cmd", label: "Toggle dark / light theme",  action: "theme" },
  ];

  function score(item, q) {
    if (!q) return 1;
    const label = item.label.toLowerCase();
    const tokens = q.toLowerCase().split(/\s+/).filter(Boolean);
    let s = 0;
    for (const t of tokens) {
      if (label.startsWith(t)) s += 4;
      else if (label.includes(t)) s += 2;
      else return 0;
    }
    return s;
  }

  function render(list, query) {
    const ranked = ITEMS
      .map((it) => ({ it, s: score(it, query) }))
      .filter((r) => r.s > 0)
      .sort((a, b) => b.s - a.s);

    list.innerHTML = "";
    if (!ranked.length) {
      list.innerHTML = `<div class="empty-state" style="padding:var(--space-5)">
        <div class="empty-state__title">No matches</div>
        <div class="empty-state__sub">Try a different search.</div>
      </div>`;
      return [];
    }

    let lastGroup = null;
    const itemEls = [];
    ranked.forEach((r, i) => {
      if (r.it.group !== lastGroup) {
        const g = document.createElement("div");
        g.className = "cmdk__group-label";
        g.textContent = r.it.group;
        list.appendChild(g);
        lastGroup = r.it.group;
      }
      const el = document.createElement("div");
      el.className = "cmdk__item";
      el.dataset.idx = String(i);
      el.innerHTML =
        `<span class="cmdk__item-icon">${ICONS[r.it.icon] || ICONS.cmd}</span>` +
        `<span class="cmdk__item-text"></span>` +
        (r.it.hint ? `<span class="cmdk__item-hint"></span>` : "");
      el.querySelector(".cmdk__item-text").textContent = r.it.label;
      if (r.it.hint) el.querySelector(".cmdk__item-hint").textContent = r.it.hint;
      el.addEventListener("click", () => activate(r.it));
      list.appendChild(el);
      itemEls.push(el);
    });
    if (itemEls.length) itemEls[0].classList.add("is-active");
    return itemEls;
  }

  function activate(item) {
    if (item.action === "theme") {
      document.querySelector("[data-theme-toggle]")?.click();
      close();
      return;
    }
    if (item.path) window.location.href = item.path;
  }

  let backdrop, input, list, items = [], idx = 0;

  function open() {
    if (!backdrop) return;
    backdrop.classList.add("is-open");
    backdrop.setAttribute("aria-hidden", "false");
    input.value = "";
    items = render(list, "");
    idx = 0;
    setTimeout(() => input.focus(), 10);
  }
  function close() {
    if (!backdrop) return;
    backdrop.classList.remove("is-open");
    backdrop.setAttribute("aria-hidden", "true");
  }
  function move(d) {
    if (!items.length) return;
    items[idx]?.classList.remove("is-active");
    idx = (idx + d + items.length) % items.length;
    items[idx]?.classList.add("is-active");
    items[idx]?.scrollIntoView({ block: "nearest" });
  }

  document.addEventListener("DOMContentLoaded", () => {
    backdrop = document.querySelector("[data-cmdk-backdrop]");
    if (!backdrop) return;
    input = backdrop.querySelector("[data-cmdk-input]");
    list = backdrop.querySelector("[data-cmdk-list]");

    document.querySelectorAll("[data-cmdk-open]").forEach((b) => b.addEventListener("click", open));

    input.addEventListener("input", () => {
      items = render(list, input.value.trim());
      idx = 0;
    });

    document.addEventListener("keydown", (e) => {
      const isCmdK = (e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k";
      if (isCmdK) { e.preventDefault(); backdrop.classList.contains("is-open") ? close() : open(); return; }
      if (!backdrop.classList.contains("is-open")) return;
      if (e.key === "Escape") { e.preventDefault(); close(); }
      else if (e.key === "ArrowDown") { e.preventDefault(); move(1); }
      else if (e.key === "ArrowUp")   { e.preventDefault(); move(-1); }
      else if (e.key === "Enter") {
        e.preventDefault();
        const el = items[idx];
        if (!el) return;
        const visible = ITEMS.filter((it) => score(it, input.value.trim()) > 0)
                             .sort((a, b) => score(b, input.value.trim()) - score(a, input.value.trim()));
        const match = visible[Number(el.dataset.idx) || 0];
        if (match) activate(match);
      }
    });

    backdrop.addEventListener("click", (e) => { if (e.target === backdrop) close(); });
  });

  global.dojaaCmdK = { open, close };
})(window);
