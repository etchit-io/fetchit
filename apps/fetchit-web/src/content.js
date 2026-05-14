// fetch>it content script. Finds existing <a href="autonomi://..."> anchors
// and decorates them with a small inline badge so users can see at a glance
// that the link routes to fetch>it (not just a dead custom-scheme URL).
//
// Deliberately conservative: only decorates anchors that *already* declare
// `href="autonomi://..."`. We do not walk arbitrary text nodes looking for
// bare 64-hex strings — that'd produce false positives on every git commit
// hash on the open web. Bare addresses are handled by the right-click
// context menu in the background service worker instead.

(() => {
  const HEX_64 = /^autonomi:\/\/([0-9a-fA-F]{64})/i;
  const ATTR = "data-fetchit-decorated";

  // One stylesheet, injected once. Scoped to a class with two leading
  // underscores so the chance of colliding with page styles is near zero.
  const STYLE_ID = "__fetchit-web-style";
  function ensureStyle() {
    if (document.getElementById(STYLE_ID)) return;
    const s = document.createElement("style");
    s.id = STYLE_ID;
    s.textContent = `
      .__fetchit-badge {
        display: inline-block;
        margin-left: 0.35em;
        padding: 0.05em 0.4em;
        border: 1px solid #B87333;
        border-radius: 4px;
        background: transparent;
        color: #B87333;
        font: 600 0.7em/1.4 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        letter-spacing: 0.02em;
        text-decoration: none;
        vertical-align: middle;
        white-space: nowrap;
        cursor: help;
        opacity: 0.85;
      }
      .__fetchit-badge:hover { opacity: 1; }
    `;
    (document.head || document.documentElement).appendChild(s);
  }

  function decorateAnchor(a) {
    if (a.hasAttribute(ATTR)) return;
    const m = HEX_64.exec(a.getAttribute("href") || "");
    if (!m) return;
    a.setAttribute(ATTR, "1");
    const addr = m[1].toLowerCase();
    const badge = document.createElement("span");
    badge.className = "__fetchit-badge";
    badge.textContent = "fetch>it";
    badge.title = `Autonomi address ${addr.slice(0, 12)}… — opens in fetch>it desktop`;
    a.insertAdjacentElement("afterend", badge);
  }

  // `i` flag → case-insensitive attribute match, so AUTONOMI:// gets caught
  // alongside autonomi://. URL schemes are case-insensitive by the RFC.
  const LINK_SEL = 'a[href^="autonomi://" i]';

  function sweep(root) {
    const scope = root && root.querySelectorAll ? root : document;
    for (const a of scope.querySelectorAll(LINK_SEL)) {
      decorateAnchor(a);
    }
  }

  ensureStyle();
  sweep(document);

  // React/Vue/etc. mount content asynchronously — observe the document so
  // links injected after our initial sweep still get decorated.
  const obs = new MutationObserver((mutations) => {
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node.nodeType !== Node.ELEMENT_NODE) continue;
        if (node.matches && node.matches(LINK_SEL)) {
          decorateAnchor(node);
        }
        sweep(node);
      }
    }
  });
  obs.observe(document.documentElement, { childList: true, subtree: true });
})();
