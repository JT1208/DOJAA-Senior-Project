// Shared Chart.js helpers — theme aware, gradient fills, soft tooltips.

(function (global) {
  const REGISTRY = [];

  function read(name, fallback) {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback;
  }

  function palette() {
    return {
      low:    read("--risk-low",    "#22c55e"),
      mid:    read("--risk-mid",    "#f59e0b"),
      high:   read("--risk-high",   "#ef4444"),
      brand:  read("--brand",       "#00e0ff"),
      brand2: read("--brand-2",     "#6366f1"),
      brand3: read("--brand-3",     "#a855f7"),
      accent: read("--accent",      "#00e0ff"),
      ink:    read("--ink",         "#e8ecf7"),
      ink2:   read("--ink-2",       "#b6bdd4"),
      muted:  read("--ink-muted",   "#7a83a0"),
      surface:read("--surface-solid", "#111729"),
      grid:   document.documentElement.getAttribute("data-theme") === "light"
              ? "rgba(20,30,60,0.08)" : "rgba(140,165,220,0.10)",
    };
  }

  function gradient(ctx, color1, color2, h) {
    const g = ctx.createLinearGradient(0, 0, 0, h || 240);
    g.addColorStop(0, color1);
    g.addColorStop(1, color2);
    return g;
  }
  function hexA(hex, alpha) {
    const v = hex.replace("#", "");
    const n = v.length === 3
      ? v.split("").map((c) => parseInt(c + c, 16))
      : [parseInt(v.slice(0, 2), 16), parseInt(v.slice(2, 4), 16), parseInt(v.slice(4, 6), 16)];
    return `rgba(${n[0]},${n[1]},${n[2]},${alpha})`;
  }

  function commonOptions(p) {
    return {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 700, easing: "easeOutQuart" },
      plugins: {
        legend: {
          position: "bottom",
          labels: {
            color: p.ink2,
            boxWidth: 10,
            boxHeight: 10,
            padding: 14,
            font: { family: "Inter, sans-serif", size: 12 },
            usePointStyle: true,
            pointStyle: "circle",
          },
        },
        tooltip: {
          backgroundColor: p.surface,
          titleColor: p.ink,
          bodyColor: p.ink2,
          borderColor: read("--border-strong", "rgba(140,165,220,0.28)"),
          borderWidth: 1,
          padding: 10,
          cornerRadius: 8,
          titleFont: { family: "Inter, sans-serif", weight: "600", size: 12 },
          bodyFont:  { family: "Inter, sans-serif", size: 12 },
          displayColors: true,
          boxPadding: 4,
        },
      },
    };
  }

  function makeDoughnut(canvas, data, labels, colors) {
    if (!canvas || !global.Chart) return null;
    const sum = data.reduce((a, b) => a + b, 0);
    if (sum === 0) return null;
    const p = palette();
    const cfg = {
      type: "doughnut",
      data: {
        labels,
        datasets: [{
          data,
          backgroundColor: colors,
          borderColor: p.surface,
          borderWidth: 3,
          hoverOffset: 6,
        }],
      },
      options: Object.assign(commonOptions(p), { cutout: "68%" }),
    };
    const chart = new Chart(canvas.getContext("2d"), cfg);
    REGISTRY.push({ canvas, chart, kind: "doughnut", data, labels, colors });
    return chart;
  }

  function makeBar(canvas, labels, values, color) {
    if (!canvas || !global.Chart) return null;
    const p = palette();
    const ctx = canvas.getContext("2d");
    const baseColor = color || p.brand;
    const cfg = {
      type: "bar",
      data: {
        labels,
        datasets: [{
          data: values,
          backgroundColor: gradient(ctx, baseColor, hexA(baseColor, 0.25), canvas.offsetHeight || 240),
          borderRadius: 6,
          barThickness: "flex",
          maxBarThickness: 38,
          hoverBackgroundColor: gradient(ctx, baseColor, hexA(baseColor, 0.6), canvas.offsetHeight || 240),
        }],
      },
      options: Object.assign(commonOptions(p), {
        plugins: Object.assign({}, commonOptions(p).plugins, { legend: { display: false } }),
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: p.muted, font: { family: "Inter, sans-serif", size: 12 } },
          },
          y: {
            beginAtZero: true,
            ticks: { color: p.muted, precision: 0, font: { family: "Inter, sans-serif", size: 12 } },
            grid: { color: p.grid, drawBorder: false },
          },
        },
      }),
    };
    const chart = new Chart(ctx, cfg);
    REGISTRY.push({ canvas, chart, kind: "bar", labels, values, color: baseColor });
    return chart;
  }

  function refreshAll() {
    // Re-render with the new theme palette.
    REGISTRY.splice(0).forEach((entry) => {
      try { entry.chart.destroy(); } catch (e) { /* noop */ }
      if (entry.kind === "doughnut") makeDoughnut(entry.canvas, entry.data, entry.labels, entry.colors);
      else if (entry.kind === "bar")  makeBar(entry.canvas, entry.labels, entry.values, entry.color);
    });
  }

  global.dojaaCharts = {
    makeDoughnut,
    makeBar,
    refreshAll,
    get PALETTE() { return palette(); },
  };
})(window);
