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
  // Both schemes route to fetch>it via the OS handler; we badge anchors
  // declared in either form. Keep this regex in sync with src/addr.js.
  const HEX_64 = /^(?:autonomi|fetchit):\/\/([0-9a-fA-F]{64})/i;
  const ATTR = "data-fetchit-decorated";
  // Opt-out marker that any page can set on an anchor or any ancestor to
  // suppress the badge. Use case: card-style anchors where an extra inline
  // span breaks the layout. (etchit.io/city sets this via CSS; pages that
  // want even tighter control can set it as an attribute.)
  const OPT_OUT = "data-no-fetchit-badge";

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

  // Returns true if the anchor's parent uses a CSS display value that treats
  // each child as a layout slot (flex/grid). Inserting an extra <span> after
  // the anchor in such a parent inserts a new slot between siblings, which
  // breaks card grids, button rows, etc. (We saw this on etchit.io/city
  // before we hid the badge there.) In that case we still flag the anchor
  // with a tooltip but skip the visible badge.
  function parentTreatsChildrenAsSlots(a) {
    const p = a.parentElement;
    if (!p) return false;
    try {
      const display = getComputedStyle(p).display;
      return /(^|\s)(flex|grid|inline-flex|inline-grid)($|\s)/.test(display);
    } catch {
      return false;
    }
  }

  function decorateAnchor(a) {
    if (a.hasAttribute(ATTR)) return;
    const m = HEX_64.exec(a.getAttribute("href") || "");
    if (!m) return;
    // Honor an opt-out on the anchor or any ancestor.
    if (a.closest(`[${OPT_OUT}]`)) {
      a.setAttribute(ATTR, "1");
      return;
    }
    const addr = m[1].toLowerCase();
    a.setAttribute(ATTR, "1");
    // Always set a tooltip — works whether or not we add a visible badge.
    // Only set if the page hasn't already set one we'd clobber.
    if (!a.title) {
      a.title = `Autonomi address ${addr.slice(0, 12)}… — opens in fetch>it desktop`;
    }
    // Skip the visible badge if it would land between siblings in a flex/grid
    // container — tooltip alone signals the link.
    if (parentTreatsChildrenAsSlots(a)) return;
    const badge = document.createElement("span");
    badge.className = "__fetchit-badge";
    badge.textContent = "fetch>it";
    badge.setAttribute("aria-hidden", "true");
    a.insertAdjacentElement("afterend", badge);
  }

  // `i` flag → case-insensitive attribute match, so AUTONOMI:// gets caught
  // alongside autonomi://. URL schemes are case-insensitive by the RFC.
  // We badge both scheme variants — autonomi:// (canonical) and fetchit://
  // (brand alias). Same target binary on the desktop side.
  const LINK_SEL = 'a[href^="autonomi://" i], a[href^="fetchit://" i]';

  function sweep(root) {
    const scope = root && root.querySelectorAll ? root : document;
    // If `root` is itself a matching anchor, decorate it directly — querySelectorAll
    // doesn't include the root element.
    if (root && root.matches && root.matches(LINK_SEL)) decorateAnchor(root);
    for (const a of scope.querySelectorAll(LINK_SEL)) decorateAnchor(a);
  }

  ensureStyle();
  sweep(document);

  // React/Vue/etc. mount content asynchronously. We coalesce mutation bursts
  // into one sweep per animation frame — busy SPAs (Twitter, GitHub, Discord)
  // can fire thousands of mutations per second, and running querySelectorAll
  // on each one is the kind of well-meaning extension that earns "this slowed
  // my browser to a crawl" reviews. One pass per frame is plenty.
  const pendingRoots = new Set();
  let scheduled = false;
  const flush = () => {
    scheduled = false;
    for (const node of pendingRoots) sweep(node);
    pendingRoots.clear();
  };
  const schedule = () => {
    if (scheduled) return;
    scheduled = true;
    (typeof requestAnimationFrame === "function"
      ? requestAnimationFrame
      : (cb) => setTimeout(cb, 16))(flush);
  };

  const obs = new MutationObserver((mutations) => {
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node.nodeType === Node.ELEMENT_NODE) pendingRoots.add(node);
      }
    }
    if (pendingRoots.size > 0) schedule();
  });
  obs.observe(document.documentElement, { childList: true, subtree: true });

  // Cheap insurance: long-lived SPAs that bfcache-restore can re-fire mutation
  // bursts. Stop observing when the page is leaving so we don't pile up state
  // across navigations.
  addEventListener(
    "pagehide",
    () => {
      obs.disconnect();
      pendingRoots.clear();
    },
    { once: true },
  );
})();
