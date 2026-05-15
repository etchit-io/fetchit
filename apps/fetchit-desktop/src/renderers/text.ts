import type { Rendition } from "../types";
import { highlightInto } from "./syntax";

export function renderText(r: Extract<Rendition, { kind: "text" }>, into: HTMLElement): void {
  const pre = document.createElement("pre");
  pre.className = "code-block";
  highlightInto(pre, r.body, r.language);
  into.appendChild(pre);
}
