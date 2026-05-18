(function () {
  document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("hdrForm");
    const input = document.getElementById("hdrInput");
    const out = document.getElementById("hdrResults");
    const { el, replace } = window.dojaaDom;

    function render(payload) {
      const rows = Object.entries(payload.results || {}).map(([header, info]) =>
        el("tr", null,
          el("td", null, el("strong", null, header)),
          el("td", null,
            info.present
              ? el("span", { class: "badge badge--low" }, "Present")
              : el("span", { class: "badge badge--high" }, "Missing")
          ),
          el("td", { class: "text-mono", style: { fontSize: "12px", wordBreak: "break-all" } }, info.value || "—")
        )
      );
      replace(out,
        el("div", { class: "card" },
          el("div", { class: "card__head" },
            el("span", null, "Results for ", el("strong", { class: "text-mono" }, payload.url)),
            el("span", { class: "badge badge--info" }, "HTTP " + payload.status_code)
          ),
          el("div", { class: "card__body card__body--tight" },
            el("table", { class: "dt" },
              el("thead", null, el("tr", null, el("th", null, "Header"), el("th", null, "Status"), el("th", null, "Value"))),
              el("tbody", null, ...rows)
            )
          )
        )
      );
    }

    form.addEventListener("submit", async function (e) {
      e.preventDefault();
      const url = input.value.trim();
      if (!url) return;
      replace(out, el("div", { class: "loading", style: { marginTop: "var(--space-3)" } }, "Fetching " + url + "…"));
      try {
        const data = await window.dojaaApi.getJson("/tools/headers/api?url=" + encodeURIComponent(url));
        render(data);
      } catch (err) {
        replace(out, el("div", { class: "alert alert--danger" }, el("span", null, err.message)));
      }
    });
  });
})();
