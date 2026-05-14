// Transforms an HTML document for safe in-iframe rendering:
//   1. injects a strict Content-Security-Policy meta that allows only the
//      fetchit:// / autonomi:// schemes (plus inline scripts/styles, which
//      the iframe sandbox already isolates) — no network egress;
//   2. forces <base href> to autonomi://<addr>/ so relative URLs resolve
//      through our protocol handler regardless of any base the document
//      tried to set (and authors' canonical scheme is autonomi://);
//   3. injects a click interceptor + back-link handler that posts up to
//      the parent window so it stays in sync with iframe nav.
// We don't rewrite `autonomi://` references in attributes — the WebView
// accepts the scheme directly because we registered it in lib.rs alongside
// fetchit://. Both resolve to the same handler.

const LINK_INTERCEPTOR = `
(function () {
  var dbgEnabled = ${JSON.stringify(!!import.meta.env.DEV)};
  function dbg(msg) {
    if (!dbgEnabled) return;
    try { parent.postMessage({ kind: 'fetchit:log', text: msg }, '*'); } catch (_) {}
  }
  function handle(e) {
    var t = e.target;
    var a = t && t.closest && t.closest('a[href]');
    if (!a) return;
    var href = a.getAttribute('href') || '';
    if (/^(?:fetchit|autonomi):\\/\\/back(?:[\\/?#]|$)/i.test(href)) {
      e.preventDefault();
      dbg('back link clicked');
      try { parent.postMessage({ kind: 'fetchit:back' }, '*'); } catch (err) { dbg('postMessage failed: ' + err); }
      return;
    }
    var m = /^(?:fetchit|autonomi):\\/\\/([0-9a-fA-F]{64})/.exec(href);
    if (!m) {
      dbg('click skipped href=' + href.slice(0, 80));
      return;
    }
    e.preventDefault();
    var newTab = e.ctrlKey || e.metaKey || e.shiftKey || e.button === 1;
    dbg('click intercept href=' + href.slice(0, 80) + ' newTab=' + newTab);
    try {
      parent.postMessage({
        kind: 'fetchit:open',
        address: m[1].toLowerCase(),
        target: newTab ? 'new' : 'current',
      }, '*');
    } catch (err) {
      dbg('postMessage failed: ' + err);
    }
  }
  document.addEventListener('click', handle, true);
  document.addEventListener('auxclick', handle, true);
  dbg('interceptor installed');
})();
`.trim();

function buildCsp(mediaBase: string): string {
  return [
    "default-src 'self' fetchit: autonomi:",
    "script-src 'self' fetchit: autonomi: 'unsafe-inline' 'unsafe-eval'",
    "style-src 'self' fetchit: autonomi: 'unsafe-inline'",
    "img-src 'self' fetchit: autonomi: data: blob:",
    `media-src 'self' fetchit: autonomi: data: blob: ${mediaBase}`,
    "font-src 'self' fetchit: autonomi: data:",
    `connect-src 'self' fetchit: autonomi: ${mediaBase}`,
    "frame-src 'none'",
    "object-src 'none'",
    "base-uri 'self' fetchit: autonomi:",
    "form-action 'self' fetchit: autonomi:",
  ].join("; ");
}

export function rewriteHtml(body: string, address: string, mediaBase: string): string {
  const doc = new DOMParser().parseFromString(body, "text/html");
  setBase(doc, `autonomi://${address}/`);
  // Strip an incoming Content-Security-Policy meta tag *before* we add ours.
  // Multiple CSP meta tags combine restrictively for fetches, but `report-uri`
  // and `report-to` are additive — a malicious SPA could phone home via
  // violation reports otherwise.
  stripIncomingCsp(doc);
  injectCsp(doc, mediaBase);
  stripResourceHints(doc);
  stripMetaRefresh(doc);
  stripAnchorPing(doc);
  injectNeuterScript(doc);
  rewriteMediaSrc(doc, mediaBase);
  injectLinkInterceptor(doc);
  return `<!doctype html>\n${doc.documentElement.outerHTML}`;
}

// `<link rel="preconnect" | "dns-prefetch" | "prefetch" | "preload" | "modulepreload">`
// are speed hints. WebKit / Chromium issue the TCP/TLS handshake (and a
// preflight in some cases) *before* CSP gets a chance to block — so an SPA
// referencing `https://fonts.gstatic.com` via preconnect still leaks the
// connection even though the actual stylesheet fetch is CSP-blocked.
// We drop them all: real stylesheets / scripts that the page actually needs
// will still be requested when used, and those requests pass through CSP.
function stripResourceHints(doc: Document): void {
  const hintRels = new Set([
    "preconnect", "dns-prefetch", "prefetch", "preload", "modulepreload",
  ]);
  for (const link of Array.from(doc.querySelectorAll("link[rel]"))) {
    const rel = (link.getAttribute("rel") ?? "").toLowerCase().trim();
    if (hintRels.has(rel)) link.remove();
  }
}

// `<meta http-equiv="refresh" content="0;url=https://attacker">` is a
// navigation, not a fetch — CSP `connect-src` doesn't cover it, and only
// some browsers gate it on `navigate-to` (still proposed). Strip them.
function stripMetaRefresh(doc: Document): void {
  for (const m of Array.from(doc.querySelectorAll('meta[http-equiv]'))) {
    if ((m.getAttribute("http-equiv") ?? "").trim().toLowerCase() === "refresh") {
      m.remove();
    }
  }
}

// Strip any Content-Security-Policy meta tag authored by the SPA — multiple
// CSPs combine restrictively for fetches but `report-uri` / `report-to` are
// additive, so a malicious page could phone home via violation reports.
function stripIncomingCsp(doc: Document): void {
  for (const m of Array.from(doc.querySelectorAll('meta[http-equiv]'))) {
    const eq = (m.getAttribute("http-equiv") ?? "").trim().toLowerCase();
    if (eq === "content-security-policy" || eq === "content-security-policy-report-only") {
      m.remove();
    }
  }
}

// `<a ping="https://tracker">` sends a background POST on click. CSP2+ covers
// it via connect-src, but older WebKit may not — strip defensively.
function stripAnchorPing(doc: Document): void {
  for (const a of Array.from(doc.querySelectorAll("a[ping], area[ping]"))) {
    a.removeAttribute("ping");
  }
}

// Inline pre-script that neuters APIs which leak data despite CSP. Runs
// before any SPA script because it's inserted as the first <script> in head.
// Each property is replaced with `undefined` (non-writable, non-configurable)
// so SPAs that re-assign or polyfill can't restore them.
const NEUTER_SCRIPT = `
(function () {
  var lock = function (obj, names) {
    for (var i = 0; i < names.length; i++) {
      try {
        Object.defineProperty(obj, names[i], {
          value: undefined, writable: false, configurable: false,
        });
      } catch (e) {}
    }
  };
  // WebRTC: ICE candidate gathering leaks local-network IPs even when no
  // connection is established. CSP3 covers RTCPeerConnection via connect-src
  // but WebKitGTK's coverage is uneven — locking the constructors out is
  // the safe play.
  lock(window, [
    "RTCPeerConnection", "webkitRTCPeerConnection", "mozRTCPeerConnection",
    "RTCDataChannel", "MediaStream",
    // Permission-prompting / sensor APIs.
    "Notification", "SharedWorker",
    // Networking that bypasses or partially bypasses fetch/connect-src.
    "WebTransport", "PresentationRequest",
  ]);
  if (window.navigator) {
    lock(navigator, [
      "geolocation", "mediaDevices", "serviceWorker",
      "share", "canShare",
      "permissions", "credentials", "presentation",
      "bluetooth", "usb", "hid", "serial",
      "wakeLock", "contacts",
      // sendBeacon: backup over CSP connect-src in case the spec/browser
      // pair doesn't gate it.
      "sendBeacon",
    ]);
  }
})();
`.trim();

function injectNeuterScript(doc: Document): void {
  const s = doc.createElement("script");
  s.textContent = NEUTER_SCRIPT;
  // After our CSP meta, before any SPA script. CSP is `head.firstChild` after
  // injectCsp, so prepending here puts neuter at index 1 (before any SPA
  // <script> that authors typically place later in <head> or in <body>).
  const csp = doc.head.querySelector('meta[http-equiv="Content-Security-Policy"]');
  if (csp && csp.nextSibling) doc.head.insertBefore(s, csp.nextSibling);
  else doc.head.insertBefore(s, doc.head.firstChild);
}

function setBase(doc: Document, href: string): void {
  for (const existing of Array.from(doc.head.querySelectorAll("base"))) {
    existing.remove();
  }
  const base = doc.createElement("base");
  base.setAttribute("href", href);
  doc.head.insertBefore(base, doc.head.firstChild);
}

function injectCsp(doc: Document, mediaBase: string): void {
  const meta = doc.createElement("meta");
  meta.setAttribute("http-equiv", "Content-Security-Policy");
  meta.setAttribute("content", buildCsp(mediaBase));
  doc.head.insertBefore(meta, doc.head.firstChild);
}

// Substitute `autonomi://<addr>` (and the alias `fetchit://<addr>`) inside
// `<audio>` / `<video>` / `<source>` src attributes with the localhost media
// server URL. WebKitGTK's media pipeline only accepts a fixed allowlist of
// schemes for `<video src>` (http/https/file/blob) — Android's
// `shouldInterceptRequest` makes `autonomi://` resolve there; this is the
// desktop equivalent: SPA authors write the declarative form, the reader
// hands the WebView a URL it can decode.
function rewriteMediaSrc(doc: Document, mediaBase: string): void {
  const prefix = /^(?:fetchit|autonomi):\/\/([0-9a-fA-F]{64})/i;
  for (const el of Array.from(doc.querySelectorAll("audio[src], video[src], source[src]"))) {
    const src = el.getAttribute("src") ?? "";
    const m = prefix.exec(src);
    if (!m) continue;
    el.setAttribute("src", `${mediaBase}/${m[1].toLowerCase()}`);
  }
}

function injectLinkInterceptor(doc: Document): void {
  const script = doc.createElement("script");
  script.textContent = LINK_INTERCEPTOR;
  doc.body.appendChild(script);
}
