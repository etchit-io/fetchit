import type { Rendition } from "../types";
import { rewriteHtml } from "./htmlRewriter";
import { mediaBase } from "../mediaUrl";

// The iframe sandbox: scripts run (SPAs need it), forms post (sandboxed
// inside CSP), and `<video>` / `<audio>` can enter fullscreen — but no
// `allow-same-origin` (the iframe is a null origin, no access to parent
// state), no top-level navigation, no popups, no pointer lock. Fullscreen
// is gated by user activation and the browser shows its own exit banner;
// the iframe still can't read parent state.
const SANDBOX = "allow-scripts allow-forms allow-fullscreen";

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
  // The sandbox token above only authorises fullscreen within a sandbox
  // that's already been granted the capability — this attribute is the
  // grant.
  iframe.setAttribute("allowfullscreen", "");
  iframe.srcdoc = rewriteHtml(r.body, address, mediaBase());

  wrap.appendChild(iframe);
  into.appendChild(wrap);
}
