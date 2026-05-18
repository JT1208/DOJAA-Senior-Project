(function () {
  document.addEventListener("DOMContentLoaded", function () {
    window.dojaaTable.init("#portsTable", { order: [[2, "desc"]] });

    const node = document.getElementById("ports-data");
    if (!node) return;
    let payload;
    try { payload = JSON.parse(node.textContent); } catch (e) { return; }
    const canvas = document.getElementById("serviceChart");
    if (canvas && payload.labels && payload.labels.length) {
      const c = window.dojaaCharts;
      // Horizontal bar — Chart.js v4 idiom: type bar + indexAxis 'y'.
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
  });
})();
