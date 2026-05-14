import type { Rendition } from "../types";
import { el, fmtBytes } from "../format";
import { mediaUrlOf } from "../mediaUrl";

export function renderVideo(
  r: Extract<Rendition, { kind: "video" }>,
  into: HTMLElement,
  src: string,
): void {
  const video = document.createElement("video");
  video.className = "rendered-video";
  video.controls = true;
  video.preload = "auto";
  video.playsInline = true;
  video.addEventListener("error", () => {
    const e = video.error;
    console.error(
      "[fetchit/video]",
      `code=${e?.code ?? "?"}`,
      `msg=${e?.message ?? ""}`,
      `src=${video.src}`,
    );
    into.replaceChildren(
      el("pre", `[failed to load ${r.mime} · ${fmtBytes(r.byteLen)}]`),
    );
  });
  try {
    const addr = src.replace(/^(?:fetchit|autonomi):\/\//i, "").replace(/[/?#].*$/, "");
    video.src = mediaUrlOf(addr);
  } catch (err) {
    into.replaceChildren(
      el("pre", `[failed to load ${r.mime} · ${fmtBytes(r.byteLen)} — ${String(err)}]`),
    );
    return;
  }
  into.appendChild(video);
}
