import type { Rendition } from "../types";
import { el, fmtBytes } from "../format";
import { mediaUrlOf } from "../mediaUrl";

export function renderAudio(
  r: Extract<Rendition, { kind: "audio" }>,
  into: HTMLElement,
  src: string,
): void {
  const wrap = document.createElement("div");
  wrap.className = "rendered-audio";

  const audio = document.createElement("audio");
  audio.controls = true;
  audio.preload = "auto";
  audio.addEventListener("error", () => {
    const e = audio.error;
    console.error(
      "[fetchit/audio]",
      `code=${e?.code ?? "?"}`,
      `msg=${e?.message ?? ""}`,
      `src=${audio.src}`,
    );
    wrap.replaceChildren(el("pre", `[failed to load ${r.mime} · ${fmtBytes(r.byteLen)}]`));
  });

  const meta = document.createElement("p");
  meta.className = "rendered-meta";
  meta.textContent = `${r.mime} · ${fmtBytes(r.byteLen)}`;

  wrap.append(audio, meta);
  into.appendChild(wrap);

  try {
    const addr = src.replace(/^(?:fetchit|autonomi):\/\//i, "").replace(/[/?#].*$/, "");
    audio.src = mediaUrlOf(addr);
  } catch (err) {
    wrap.replaceChildren(
      el("pre", `[failed to load ${r.mime} · ${fmtBytes(r.byteLen)} — ${String(err)}]`),
    );
  }
}
