(function () {
  document.addEventListener("DOMContentLoaded", function () {
    const $table = window.jQuery("#hostsTable");
    if (!$table.length) return;

    // Read presets from query string (passed by blueprint).
    let presets = { source: null, risk: null, port: null };
    try { presets = JSON.parse(document.getElementById("hosts-presets").textContent); } catch (e) {}

    const sourceSel = document.getElementById("source-filter");
    const riskSel = document.getElementById("risk-filter");
    const portInp = document.getElementById("port-filter");
    const clearBtn = document.getElementById("clear-filters");
    const countLabel = document.getElementById("hostsTableCount");

    let portFilter = presets.port ? presets.port.split(",").map((s) => s.trim()).filter(Boolean) : [];
    let sourceFilter = presets.source || "";
    let riskFilter = presets.risk || "";

    window.jQuery.fn.dataTable.ext.search.push(function (settings, _data, idx) {
      const tr = settings.aoData[idx].nTr;
      if (!tr) return true;
      if (sourceFilter && tr.dataset.source !== sourceFilter) return false;
      if (riskFilter && tr.dataset.bucket !== riskFilter) return false;
      if (portFilter.length > 0) {
        if (!portFilter.includes(tr.dataset.port)) return false;
      }
      return true;
    });

    const table = window.dojaaTable.init("#hostsTable", {
      order: [[5, "desc"]],
      columnDefs: [{ targets: [4], orderable: false }],
    });

    function syncUrl() {
      const params = new URLSearchParams();
      if (sourceFilter) params.set("source", sourceFilter);
      if (riskFilter)   params.set("risk", riskFilter);
      if (portFilter.length) params.set("port", portFilter.join(","));
      const q = params.toString();
      window.history.replaceState({}, "", q ? "?" + q : window.location.pathname);
    }

    function updateCount() {
      const info = table.page.info();
      countLabel.textContent =
        info.recordsDisplay === info.recordsTotal
          ? "Showing " + info.recordsTotal + " rows"
          : "Showing " + info.recordsDisplay + " of " + info.recordsTotal + " rows";
    }

    sourceSel.addEventListener("change", function (e) {
      sourceFilter = e.target.value; table.draw(); syncUrl(); updateCount();
    });
    riskSel.addEventListener("change", function (e) {
      riskFilter = e.target.value; table.draw(); syncUrl(); updateCount();
    });
    portInp.addEventListener("input", function (e) {
      portFilter = e.target.value.split(",").map((s) => s.trim()).filter(Boolean);
      table.draw(); syncUrl(); updateCount();
    });
    clearBtn.addEventListener("click", function () {
      sourceFilter = ""; riskFilter = ""; portFilter = [];
      sourceSel.value = ""; riskSel.value = ""; portInp.value = "";
      table.search("").draw(); syncUrl(); updateCount();
    });

    table.on("draw.dt", updateCount);
    // Initial draw to apply presets, then update count.
    table.draw();
    updateCount();
  });
})();
