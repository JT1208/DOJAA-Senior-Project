(function () {
  document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("dnsForm");
    const input = document.getElementById("dnsInput");
    const out = document.getElementById("dnsResults");
    const { el, replace } = window.dojaaDom;

    function render(payload) {
      const rows = Object.entries(payload.records || {}).map(([type, values]) =>
        el("tr", null,
          el("td", { class: "text-mono" }, type),
          values.length
            ? el("td", null, ...values.map((v, i) => el("div", { class: "text-mono", style: { fontSize: "13px" } }, v)))
            : el("td", { class: "text-muted" }, "None found")
        )
      );
      replace(out,
        el("div", { class: "card" },
          el("div", { class: "card__head" }, "Results for ", el("strong", null, payload.domain)),
          el("div", { class: "card__body card__body--tight" },
            el("table", { class: "dt" },
              el("thead", null, el("tr", null, el("th", null, "Record"), el("th", null, "Values"))),
              el("tbody", null, ...rows)
            )
          )
        )
      );
    }

    form.addEventListener("submit", async function (e) {
      e.preventDefault();
      const domain = input.value.trim();
      if (!domain) return;
      replace(out, el("div", { class: "loading", style: { marginTop: "var(--space-3)" } }, "Looking up " + domain + "…"));
      try {
        const data = await window.dojaaApi.getJson("/tools/dns/api?domain=" + encodeURIComponent(domain));
        render(data);
      } catch (err) {
        replace(out, el("div", { class: "alert alert--danger" }, el("span", null, err.message)));
      }
    });
  });
})();
