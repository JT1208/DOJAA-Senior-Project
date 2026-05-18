(function () {
  document.addEventListener("DOMContentLoaded", function () {
    const $table = window.jQuery("#hostsTable");
    if (!$table.length) return;

    let portFilter = [];
    let sourceFilter = "";
    let riskFilter = "";

    // Custom DataTables row filter — combines source / risk / port.
    window.jQuery.fn.dataTable.ext.search.push(function (settings, _data, _idx, rowData, _i, row) {
      const tr = settings.aoData[_idx].nTr;
      if (!tr) return true;
      if (sourceFilter && tr.dataset.source !== sourceFilter) return false;
      if (riskFilter && tr.dataset.bucket !== riskFilter) return false;
      if (portFilter.length > 0) {
        const p = tr.dataset.port;
        if (!portFilter.includes(p)) return false;
      }
      return true;
    });

    const table = window.dojaaTable.init("#hostsTable", {
      order: [[5, "desc"]],
      columnDefs: [
        { targets: [4], orderable: false },
      ],
    });

    document.getElementById("source-filter").addEventListener("change", function (e) {
      sourceFilter = e.target.value;
      table.draw();
    });
    document.getElementById("risk-filter").addEventListener("change", function (e) {
      riskFilter = e.target.value;
      table.draw();
    });
    document.getElementById("port-filter").addEventListener("input", function (e) {
      portFilter = e.target.value
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      table.draw();
    });
  });
})();
