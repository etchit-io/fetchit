import type { Rendition } from "../types";
import { el } from "../format";

export function renderJson(r: Extract<Rendition, { kind: "json" }>, into: HTMLElement): void {
  into.appendChild(el("pre", r.pretty));
}
