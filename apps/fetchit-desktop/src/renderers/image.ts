import type { Rendition } from "../types";
import { el, fmtBytes } from "../format";

export function renderImage(
  r: Extract<Rendition, { kind: "image" }>,
  into: HTMLElement,
  src: string,
): void {
  const img = document.createElement("img");
  img.className = "rendered-image";
  img.alt = r.mime;
  img.draggable = false;
  img.onerror = () => {
    into.replaceChildren(el("pre", `[failed to load ${r.mime} · ${fmtBytes(r.byteLen)}]`));
  };
  img.src = src;
  into.appendChild(img);
}
