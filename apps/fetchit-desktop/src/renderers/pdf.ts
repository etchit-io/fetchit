import type { Rendition } from "../types";
import { el, fmtBytes } from "../format";

export function renderPdf(r: Extract<Rendition, { kind: "pdf" }>, into: HTMLElement): void {
  into.appendChild(el("pre", `[PDF · ${fmtBytes(r.byteLen)} · in-app reader coming next]`));
}
