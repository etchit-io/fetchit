// Inline-in-bubble preview for `autonomi://<addr>` links.
//
// Lazy by design — nothing is fetched until the user clicks Preview.
// Lightweight kinds (text, image, json, tabular, markdown-as-text) are
// rendered in place by reusing the main renderer pipeline; heavyweight
// kinds (audio, video, pdf, html SPAs, archives, binaries) fall back
// to "Open in reader".

import { invoke } from "@tauri-apps/api/core";
import type { Rendition } from "../types";
import { renderText } from "../renderers/text";
import { renderJson } from "../renderers/json";
import { renderImage } from "../renderers/image";
import { renderTabular } from "../renderers/tabular";
import { renderEtchitEnvelope } from "../renderers/etchitEnvelope";

const ADDR_RE = /^[0-9a-fA-F]{64}$/;

const HEAVY_KINDS = new Set<Rendition["kind"]>([
  "audio",
  "video",
  "pdf",
  "html",
  "archive",
  "binary",
]);

export interface PreviewHandlers {
  onOpen: (url: string) => void;
}

export function mountAutonomiPreview(
  parent: HTMLElement,
  addr: string,
  handlers: PreviewHandlers,
): void {
  if (!ADDR_RE.test(addr)) return;

  const card = document.createElement("div");
  card.className = "chat-preview";

  const head = document.createElement("div");
  head.className = "chat-preview__head";

  const icon = document.createElement("span");
  icon.className = "chat-preview__icon";
  icon.setAttribute("aria-hidden", "true");
  icon.textContent = "⌬";

  const label = document.createElement("span");
  label.className = "chat-preview__addr";
  label.textContent = `autonomi://${addr.slice(0, 8)}…${addr.slice(-4)}`;
  label.title = `autonomi://${addr}`;

  head.appendChild(icon);
  head.appendChild(label);

  const actions = document.createElement("div");
  actions.className = "chat-preview__actions";

  const previewBtn = document.createElement("button");
  previewBtn.type = "button";
  previewBtn.className = "chat-preview__btn";
  previewBtn.textContent = "Preview";

  const openBtn = document.createElement("button");
  openBtn.type = "button";
  openBtn.className = "chat-preview__btn chat-preview__btn--ghost";
  openBtn.textContent = "Open";
  openBtn.addEventListener("click", () =>
    handlers.onOpen(`autonomi://${addr}`),
  );

  actions.appendChild(previewBtn);
  actions.appendChild(openBtn);

  const slot = document.createElement("div");
  slot.className = "chat-preview__slot";
  slot.hidden = true;

  const status = document.createElement("div");
  status.className = "chat-preview__status";
  status.hidden = true;

  card.appendChild(head);
  card.appendChild(actions);
  card.appendChild(status);
  card.appendChild(slot);

  previewBtn.addEventListener("click", async () => {
    previewBtn.disabled = true;
    status.hidden = false;
    status.textContent = "Fetching…";
    try {
      const r = await invoke<Rendition>("fetch_and_render", {
        addr,
        tabId: `bubble-preview-${addr}`,
      });
      status.hidden = true;
      slot.hidden = false;
      previewBtn.hidden = true;
      renderInline(r, addr, slot, handlers);
    } catch (e) {
      status.textContent = `Preview failed: ${(e as Error).message}`;
      previewBtn.disabled = false;
    }
  });

  parent.appendChild(card);
}

function renderInline(
  r: Rendition,
  addr: string,
  into: HTMLElement,
  handlers: PreviewHandlers,
): void {
  into.replaceChildren();
  into.classList.add("chat-preview__rendered");
  into.dataset.kind = r.kind;

  if (HEAVY_KINDS.has(r.kind)) {
    renderHeavyFallback(r, addr, into, handlers);
    return;
  }

  switch (r.kind) {
    case "text":
      renderText(r, into);
      return;
    case "etchitEnvelope":
      renderEtchitEnvelope(r, into);
      return;
    case "json":
      renderJson(r, into);
      return;
    case "tabular":
      renderTabular(r, into);
      return;
    case "image":
      renderImage(r, into, `autonomi://${addr}`);
      return;
    default:
      renderHeavyFallback(r, addr, into, handlers);
  }
}

function renderHeavyFallback(
  r: Rendition,
  addr: string,
  into: HTMLElement,
  handlers: PreviewHandlers,
): void {
  const wrap = document.createElement("div");
  wrap.className = "chat-preview__heavy";

  const desc = document.createElement("span");
  desc.textContent = describeKind(r);

  const open = document.createElement("button");
  open.type = "button";
  open.className = "chat-preview__btn";
  open.textContent = "Open in reader";
  open.addEventListener("click", () => handlers.onOpen(`autonomi://${addr}`));

  wrap.appendChild(desc);
  wrap.appendChild(open);
  into.appendChild(wrap);
}

function describeKind(r: Rendition): string {
  switch (r.kind) {
    case "audio":
      return `Audio · ${r.mime}`;
    case "video":
      return `Video · ${r.mime}`;
    case "pdf":
      return "PDF document";
    case "html":
      return "HTML page";
    case "archive":
      return `Archive · ${r.entries.length} entries`;
    case "binary":
      return `Binary · ${r.mime}`;
    default:
      return r.kind;
  }
}

export function extractAutonomiAddresses(body: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const m of body.matchAll(/autonomi:\/\/([0-9a-fA-F]{64})/g)) {
    const a = m[1].toLowerCase();
    if (seen.has(a)) continue;
    seen.add(a);
    out.push(a);
  }
  return out;
}
