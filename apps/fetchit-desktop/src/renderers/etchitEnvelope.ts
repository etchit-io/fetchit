import type { Rendition } from "../types";
import { el } from "../format";

export function renderEtchitEnvelope(
  r: Extract<Rendition, { kind: "etchitEnvelope" }>,
  into: HTMLElement,
): void {
  if (r.title) into.appendChild(el("h2", r.title));
  into.appendChild(el("pre", r.content));
}
