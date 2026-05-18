// Shared Chart.js helpers + the DOJAA palette.

(function (global) {
  const PALETTE = {
    low:     getComputedStyle(document.documentElement).getPropertyValue("--risk-low").trim()    || "#1f8a4c",
    mid:     getComputedStyle(document.documentElement).getPropertyValue("--risk-mid").trim()    || "#c47a00",
    high:    getComputedStyle(document.documentElement).getPropertyValue("--risk-high").trim()   || "#b3261e",
    brand:   getComputedStyle(document.documentElement).getPropertyValue("--brand").trim()       || "#1f3a93",
    accent:  getComputedStyle(document.documentElement).getPropertyValue("--accent").trim()      || "#00a6a6",
    muted:   getComputedStyle(document.documentElement).getPropertyValue("--ink-muted").trim()   || "#6c7488",
  };

  function makeDoughnut(canvas, data, labels, colors) {
    if (!canvas || !global.Chart) return null;
    const sum = data.reduce((a, b) => a + b, 0);
    if (sum === 0) return null;
    return new Chart(canvas.getContext("2d"), {
      type: "doughnut",
      data: {
        labels,
        datasets: [{ data, backgroundColor: colors, borderWidth: 0 }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: "bottom", labels: { boxWidth: 10 } } },
        cutout: "60%",
      },
    });
  }

  function makeBar(canvas, labels, values, color) {
    if (!canvas || !global.Chart) return null;
    return new Chart(canvas.getContext("2d"), {
      type: "bar",
      data: {
        labels,
        datasets: [{
          data: values,
          backgroundColor: color || PALETTE.brand,
          borderRadius: 4,
          barThickness: "flex",
          maxBarThickness: 32,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false }, ticks: { color: PALETTE.muted } },
          y: { beginAtZero: true, ticks: { color: PALETTE.muted, precision: 0 },
               grid: { color: "#eef0f4" } },
        },
      },
    });
  }

  global.dojaaCharts = { makeDoughnut, makeBar, PALETTE };
})(window);
