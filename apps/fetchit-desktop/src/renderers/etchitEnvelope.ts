import type { Rendition } from "../types";
import { el } from "../format";
import { highlightInto } from "./syntax";

export function renderEtchitEnvelope(
  r: Extract<Rendition, { kind: "etchitEnvelope" }>,
  into: HTMLElement,
): void {
  if (r.title) into.appendChild(el("h2", r.title));
  const pre = document.createElement("pre");
  pre.className = "code-block";
  highlightInto(pre, r.content, r.language);
  into.appendChild(pre);
}
