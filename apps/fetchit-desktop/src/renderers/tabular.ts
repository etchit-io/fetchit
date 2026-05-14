import type { Rendition } from "../types";
import { el } from "../format";

export function renderTabular(
  r: Extract<Rendition, { kind: "tabular" }>,
  into: HTMLElement,
): void {
  const table = el("table");
  const head = el("tr");
  for (const c of r.columns) head.appendChild(el("th", c));
  table.appendChild(head);
  for (const row of r.rows) {
    const tr = el("tr");
    for (const cell of row) tr.appendChild(el("td", cell));
    table.appendChild(tr);
  }
  into.appendChild(table);
}
