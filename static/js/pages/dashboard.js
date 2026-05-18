(function () {
  document.addEventListener("DOMContentLoaded", function () {
    const dataNode = document.getElementById("dashboard-data");
    if (!dataNode) return;
    let payload = {};
    try { payload = JSON.parse(dataNode.textContent); } catch (e) { return; }

    const c = window.dojaaCharts;

    const exposureCanvas = document.getElementById("exposureChart");
    if (exposureCanvas && payload.exposure) {
      c.makeBar(exposureCanvas, ["SSH (22)", "HTTP (80)", "HTTPS (443)"], payload.exposure);
    }

    const riskCanvas = document.getElementById("riskChart");
    if (riskCanvas && payload.risk) {
      c.makeDoughnut(
        riskCanvas,
        payload.risk,
        ["Low", "Medium", "High"],
        [c.PALETTE.low, c.PALETTE.mid, c.PALETTE.high]
      );
    }
  });
})();
