(function () {
  document.addEventListener("DOMContentLoaded", function () {
    const c = window.dojaaCharts;
    let tierFilter = "";

    window.jQuery.fn.dataTable.ext.search.push(function (settings, _data, idx) {
      const tr = settings.aoData[idx].nTr;
      if (!tr || !tr.dataset.bucket) return true;
      if (tierFilter && tr.dataset.bucket !== tierFilter) return false;
      return true;
    });

    const topTable = window.dojaaTable.init("#topAssetsTable", {
      paging: false,
      info: false,
      order: [[3, "desc"]],
      columnDefs: [{ targets: [5], orderable: false }],
    });

    document.getElementById("tier-filter").addEventListener("change", function (e) {
      tierFilter = e.target.value;
      topTable.draw();
    });

    document.querySelectorAll(".card .card__body--tight table.dt").forEach((t) => {
      if (t.id === "topAssetsTable") return;
      window.dojaaTable.init(t, { paging: false, info: false });
    });

    const node = document.getElementById("risk-data");
    if (!node) return;
    let payload;
    try { payload = JSON.parse(node.textContent); } catch (e) { return; }

    c.makeDoughnut(
      document.getElementById("riskChart"),
      payload.tiers,
      ["Low", "Medium", "High"],
      [c.PALETTE.low, c.PALETTE.mid, c.PALETTE.high]
    );

    const sourceCanvas = document.getElementById("sourceChart");
    if (sourceCanvas && window.Chart) {
      new Chart(sourceCanvas.getContext("2d"), {
        type: "bar",
        data: {
          labels: ["Shodan", "Censys"],
          datasets: [
            { label: "Low",    data: [payload.source.shodan[0], payload.source.censys[0]], backgroundColor: c.PALETTE.low,  borderRadius: 4 },
            { label: "Medium", data: [payload.source.shodan[1], payload.source.censys[1]], backgroundColor: c.PALETTE.mid,  borderRadius: 4 },
            { label: "High",   data: [payload.source.shodan[2], payload.source.censys[2]], backgroundColor: c.PALETTE.high, borderRadius: 4 },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { position: "bottom", labels: { boxWidth: 10 } } },
          scales: {
            x: { stacked: true, ticks: { color: c.PALETTE.muted } },
            y: { stacked: true, beginAtZero: true, ticks: { color: c.PALETTE.muted, precision: 0 } },
          },
        },
      });
    }
  });
})();
