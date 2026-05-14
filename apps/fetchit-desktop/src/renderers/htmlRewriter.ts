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
  injectCsp(doc, mediaBase);
  rewriteMediaSrc(doc, mediaBase);
  injectLinkInterceptor(doc);
  return `<!doctype html>\n${doc.documentElement.outerHTML}`;
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
