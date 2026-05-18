// Shared fetch wrapper that always returns JSON and normalises errors.

(function (global) {
  async function getJson(url) {
    let resp;
    try {
      resp = await fetch(url, { headers: { Accept: "application/json" } });
    } catch (e) {
      throw new Error("Network request failed — check your connection.");
    }
    let body = null;
    try { body = await resp.json(); } catch (e) { /* empty */ }
    if (!resp.ok) {
      const msg = (body && body.error) || `HTTP ${resp.status}`;
      throw new Error(msg);
    }
    if (body && body.error) throw new Error(body.error);
    return body;
  }

  global.dojaaApi = { getJson };
})(window);
