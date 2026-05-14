import type { Rendition } from "../types";
import { el, fmtBytes } from "../format";

export function renderArchive(
  r: Extract<Rendition, { kind: "archive" }>,
  into: HTMLElement,
): void {
  const lines = r.entries
    .map((e) => `${e.path}${e.size != null ? `  (${fmtBytes(e.size)})` : ""}`)
    .join("\n");
  into.appendChild(el("pre", `${r.entries.length} entries\n\n${lines}`));
}
