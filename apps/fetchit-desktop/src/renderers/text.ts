import type { Rendition } from "../types";
import { el } from "../format";

export function renderText(r: Extract<Rendition, { kind: "text" }>, into: HTMLElement): void {
  into.appendChild(el("pre", r.body));
}
