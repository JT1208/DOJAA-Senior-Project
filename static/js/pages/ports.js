(function () {
  document.addEventListener("DOMContentLoaded", function () {
    const tableEl = document.getElementById("portsTable");
    if (!tableEl) return;

    let portQuery = "";
    let riskyOnly = false;

    window.jQuery.fn.dataTable.ext.search.push(function (settings, data, idx) {
      const tr = settings.aoData[idx].nTr;
      if (!tr) return true;
      if (riskyOnly && tr.dataset.risky !== "yes") return false;
      if (portQuery) {
        const port = (data[0] || "").toString().toLowerCase();
        const hint = (data[1] || "").toString().toLowerCase();
        if (!(port.includes(portQuery) || hint.includes(portQuery))) return false;
      }
      return true;
    });

    const table = window.dojaaTable.init("#portsTable", {
      order: [[2, "desc"]],
      columnDefs: [{ targets: [4], orderable: false }],
    });

    const countLabel = document.getElementById("portsCount");
    function updateCount() {
      const info = table.page.info();
      countLabel.textContent =
        info.recordsDisplay === info.recordsTotal
          ? info.recordsTotal + " rows"
          : info.recordsDisplay + " of " + info.recordsTotal + " rows";
    }
    table.on("draw.dt", updateCount);

    document.getElementById("port-search").addEventListener("input", function (e) {
      portQuery = (e.target.value || "").trim().toLowerCase();
      table.draw();
    });
    document.getElementById("risky-only").addEventListener("change", function (e) {
      riskyOnly = !!e.target.checked;
      table.draw();
    });

    // Service chart.
    const node = document.getElementById("ports-data");
    if (!node) return;
    let payload;
    try { payload = JSON.parse(node.textContent); } catch (e) { return; }
    const canvas = document.getElementById("serviceChart");
    if (canvas && payload.labels && payload.labels.length) {
      const c = window.dojaaCharts;
      new Chart(canvas.getContext("2d"), {
        type: "bar",
        data: {
          labels: payload.labels,
          datasets: [{ data: payload.values, backgroundColor: c.PALETTE.brand, borderRadius: 4 }],
        },
        options: {
          indexAxis: "y",
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { beginAtZero: true, ticks: { precision: 0, color: c.PALETTE.muted } },
            y: { ticks: { color: c.PALETTE.muted } },
          },
        },
      });
    }

    updateCount();
  });
})();
