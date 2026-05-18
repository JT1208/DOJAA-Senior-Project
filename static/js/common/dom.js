// Tiny safe-DOM helpers so we never build HTML by string-concatenating
// untrusted values. Used by tools/* pages.

(function (global) {
  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v === false || v === null || v === undefined) continue;
        if (k === "class")        node.className = v;
        else if (k === "style")   Object.assign(node.style, v);
        else if (k.startsWith("on") && typeof v === "function")
                                  node.addEventListener(k.slice(2).toLowerCase(), v);
        else if (k === "html")    node.innerHTML = v;   // caller's responsibility
        else                      node.setAttribute(k, v);
      }
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      node.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function replace(node, ...children) {
    clear(node);
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      node.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
    }
  }

  global.dojaaDom = { el, clear, replace };
})(window);
