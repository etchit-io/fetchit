import type { Rendition } from "../types";
import { el, fmtBytes } from "../format";

export function renderBinary(
  r: Extract<Rendition, { kind: "binary" }>,
  into: HTMLElement,
): void {
  into.appendChild(el("pre", `[${r.mime} · ${fmtBytes(r.byteLen)} · no preview available]`));
}
