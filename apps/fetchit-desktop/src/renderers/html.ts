import type { Rendition } from "../types";
import { rewriteHtml } from "./htmlRewriter";
import { mediaBase } from "../mediaUrl";

// The iframe sandbox: scripts run (SPAs need it), forms post (sandboxed
// inside CSP) — but no `allow-same-origin` (the iframe is a null origin,
// no access to parent state), no top-level navigation, no popups, no
// pointer lock. Fullscreen for <video>/<audio> is granted via the
// separate `allowfullscreen` attribute below, not via a sandbox token.
//
// (`allow-fullscreen` is NOT a real sandbox token per the HTML spec —
// Chromium warns "invalid sandbox flag" if you list it; WebKit silently
// ignores. Keep it OUT of this string.)
const SANDBOX = "allow-scripts allow-forms";

export function renderHtml(
  r: Extract<Rendition, { kind: "html" }>,
  into: HTMLElement,
  address: string,
): void {
  const wrap = document.createElement("div");
  wrap.className = "rendered-html";

  const iframe = document.createElement("iframe");
  iframe.title = "fetchit content";
  iframe.setAttribute("referrerpolicy", "no-referrer");
  iframe.setAttribute("sandbox", SANDBOX);
  // Permits <video> / <audio> requestFullscreen() inside the iframe.
  // This is the legacy attribute that actually authorises fullscreen
  // (the modern equivalent is `allow="fullscreen"`, also valid; we use
  // the attribute for maximum WebView compatibility).
  iframe.setAttribute("allowfullscreen", "");
  iframe.srcdoc = rewriteHtml(r.body, address, mediaBase());

  wrap.appendChild(iframe);
  into.appendChild(wrap);
}
