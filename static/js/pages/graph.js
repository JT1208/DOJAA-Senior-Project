(function () {
  document.addEventListener("DOMContentLoaded", function () {
    if (!window.vis) return;
    const node = document.getElementById("graph-data");
    if (!node) return;
    let raw;
    try { raw = JSON.parse(node.textContent); } catch (e) { return; }
    if (!raw || !raw.length) return;

    const assets = Array.from(new Map(raw.filter((a) => a && a.ip).map((a) => [a.ip, a])).values());

    const palette = window.dojaaCharts.PALETTE;

    function classify(a) {
      const p = Number(a.port);
      if (p === 22) return "SSH";
      if (p === 80 || p === 443) return "WEB";
      return "OTHER";
    }
    function riskColor(score) {
      const r = Number(score) || 0;
      if (r >= 70) return palette.high;
      if (r >= 30) return palette.mid;
      return palette.low;
    }

    const nodes = [];
    const edges = [];

    nodes.push({
      id: "internet", label: "EXTERNAL ATTACK SURFACE", shape: "box",
      color: { background: palette.brand, border: palette.brand },
      font: { color: "#fff", size: 16 }, margin: 14,
    });

    const hubs = { SSH: palette.high, WEB: palette.brand, OTHER: palette.muted };
    for (const [name, color] of Object.entries(hubs)) {
      nodes.push({
        id: name, label: name + " SERVICES", shape: "box",
        color: { background: color, border: color },
        font: { color: "#fff", size: 14 }, margin: 12,
      });
      edges.push({ from: "internet", to: name, width: 2, color: { color: "#cdd3df" } });
    }

    for (const a of assets) {
      const ip = a.ip;
      const group = classify(a);
      const risk = Number(a.risk_score) || 0;
      const safe = (s) => (s == null ? "—" : String(s).replace(/[<>&]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" }[c])));
      nodes.push({
        id: ip, label: ip, shape: "dot", size: 14,
        color: { background: riskColor(risk), border: "#1f2536" },
        font: { size: 11 },
        title:
          `<b>IP:</b> ${safe(ip)}<br>` +
          `<b>Port:</b> ${safe(a.port)}<br>` +
          `<b>Service:</b> ${safe(a.service)}<br>` +
          `<b>Risk:</b> ${safe(a.risk_score)}<br>` +
          `<b>Provider:</b> ${safe(a.provider)}<br>` +
          `<b>Banner:</b> ${safe((a.banner || "").slice(0, 120))}`,
      });
      edges.push({ from: group, to: ip, width: 1, color: { color: "#dee2ec" } });
    }

    const container = document.getElementById("graph");
    const network = new window.vis.Network(
      container,
      { nodes: new window.vis.DataSet(nodes), edges: new window.vis.DataSet(edges) },
      {
        layout: { improvedLayout: true },
        physics: {
          enabled: true,
          barnesHut: { gravitationalConstant: -8000, springLength: 160, springConstant: 0.03 },
          stabilization: { iterations: 250 },
        },
        nodes: { borderWidth: 2, shadow: true },
        edges: { smooth: { type: "dynamic" } },
        interaction: { hover: true, tooltipDelay: 100, zoomView: true, dragView: true },
      }
    );

    network.once("stabilizationIterationsDone", () => network.fit({ animation: { duration: 600 } }));

    container.addEventListener("dblclick", () => {
      const sel = network.getSelectedNodes();
      const id = sel && sel[0];
      if (id && id !== "internet" && id !== "SSH" && id !== "WEB" && id !== "OTHER") {
        window.location.href = "/hosts/" + encodeURIComponent(id);
      }
    });
  });
})();
