import type { Rendition } from "../types";
import { rewriteHtml } from "./htmlRewriter";
import { mediaBase } from "../mediaUrl";

// The iframe sandbox: scripts run (SPAs need it) and forms post (sandboxed
// inside CSP), but no `allow-same-origin` (the iframe is a null origin, no
// access to parent state), no top-level navigation, no popups, no pointer lock.
const SANDBOX = "allow-scripts allow-forms";

export function renderHtml(
  r: Extract<Rendition, { kind: "html" }>,
  into: HTMLElement,
  address: string,
): void {
  const wrap = document.createElement("div");
  wrap.className = "rendered-html";

  const iframe = document.createElement("iframe");
  iframe.title = "fetch>it content";
  iframe.setAttribute("referrerpolicy", "no-referrer");
  iframe.setAttribute("sandbox", SANDBOX);
  iframe.srcdoc = rewriteHtml(r.body, address, mediaBase());

  wrap.appendChild(iframe);
  into.appendChild(wrap);
}
