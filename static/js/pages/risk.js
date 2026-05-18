(function () {
  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("table.dt").forEach((t) => window.dojaaTable.init(t, { paging: false, info: false }));
    const node = document.getElementById("risk-data");
    if (!node) return;
    let payload;
    try { payload = JSON.parse(node.textContent); } catch (e) { return; }
    const c = window.dojaaCharts;
    c.makeDoughnut(
      document.getElementById("riskChart"),
      payload.counts,
      ["Low", "Medium", "High"],
      [c.PALETTE.low, c.PALETTE.mid, c.PALETTE.high]
    );
  });
})();
