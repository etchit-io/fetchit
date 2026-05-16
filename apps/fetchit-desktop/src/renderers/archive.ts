// Archive renderer. fetchit-core hands us the index (names + sizes);
// this surface lets the user drill into each entry and either preview
// it inline or save it to disk. Inner-entry bytes come back from
// `extract_archive_entry` and get sniffed/rendered locally — we do
// **not** re-run the full core handler-registry on extracted bytes
// because (a) the binary kinds (image/audio/video/pdf) want bytes
// served over the `fetchit://` URI scheme, which doesn't address
// inner entries today, and (b) extension-based dispatch covers the
// common cases (images, audio, video, pdf, text). Unknown kinds get
// a Save As… affordance.

import { invoke } from "@tauri-apps/api/core";
import { save as saveDialog } from "@tauri-apps/plugin-dialog";

import type { Rendition } from "../types";
import { fmtBytes } from "../format";

interface InnerEntry {
  path: string;
  size: number | null;
}

export function renderArchive(
  r: Extract<Rendition, { kind: "archive" }>,
  into: HTMLElement,
  address: string,
): void {
  const root = document.createElement("div");
  root.className = "archive-view";

  root.appendChild(renderHeader(r.entries.length, address));
  const listEl = renderList(r.entries, address);
  root.appendChild(listEl);

  into.appendChild(root);
}

function renderHeader(count: number, address: string): HTMLElement {
  const header = document.createElement("header");
  header.className = "archive-header";

  const title = document.createElement("p");
  title.className = "archive-title";
  title.textContent = `${count} ${count === 1 ? "entry" : "entries"}`;
  header.appendChild(title);

  const saveBtn = document.createElement("button");
  saveBtn.type = "button";
  saveBtn.className = "archive-save-all";
  saveBtn.textContent = "Save archive…";
  saveBtn.addEventListener("click", () => {
    void saveWholeArchive(address);
  });
  header.appendChild(saveBtn);

  return header;
}

function renderList(entries: InnerEntry[], address: string): HTMLElement {
  const ul = document.createElement("ul");
  ul.className = "archive-list";
  for (const entry of entries) {
    ul.appendChild(renderRow(entry, address));
  }
  return ul;
}

function renderRow(entry: InnerEntry, address: string): HTMLLIElement {
  const li = document.createElement("li");
  li.className = "archive-row";

  const main = document.createElement("div");
  main.className = "archive-row-main";

  const path = document.createElement("p");
  path.className = "archive-row-path";
  path.textContent = entry.path;

  const meta = document.createElement("p");
  meta.className = "archive-row-meta";
  meta.textContent = entry.size != null ? fmtBytes(entry.size) : "";

  main.append(path, meta);

  const actions = document.createElement("div");
  actions.className = "archive-row-actions";

  const viewBtn = document.createElement("button");
  viewBtn.type = "button";
  viewBtn.className = "archive-row-view";
  viewBtn.textContent = "View";
  viewBtn.addEventListener("click", () => {
    void toggleView(li, entry, address, viewBtn);
  });

  const saveBtn = document.createElement("button");
  saveBtn.type = "button";
  saveBtn.className = "archive-row-save";
  saveBtn.textContent = "Save";
  saveBtn.addEventListener("click", () => {
    void saveEntry(entry, address);
  });

  actions.append(viewBtn, saveBtn);

  li.append(main, actions);
  return li;
}

async function toggleView(
  row: HTMLLIElement,
  entry: InnerEntry,
  address: string,
  btn: HTMLButtonElement,
): Promise<void> {
  const existing = row.querySelector(".archive-row-preview") as HTMLElement | null;
  if (existing) {
    existing.remove();
    btn.textContent = "View";
    return;
  }
  btn.textContent = "Loading…";
  btn.disabled = true;
  try {
    const bytes = await extractEntry(address, entry.path);
    const preview = renderPreview(entry, bytes);
    row.appendChild(preview);
    btn.textContent = "Hide";
  } catch (e) {
    const errBox = document.createElement("p");
    errBox.className = "archive-row-preview archive-row-error";
    errBox.textContent = `Couldn't open: ${errMessage(e)}`;
    row.appendChild(errBox);
    btn.textContent = "View";
  } finally {
    btn.disabled = false;
  }
}

async function extractEntry(address: string, entryPath: string): Promise<Uint8Array> {
  const raw = await invoke<number[]>("extract_archive_entry", {
    addr: address,
    entryPath,
  });
  return Uint8Array.from(raw);
}

function renderPreview(entry: InnerEntry, bytes: Uint8Array): HTMLElement {
  const wrap = document.createElement("div");
  wrap.className = "archive-row-preview";
  const kind = inferKind(entry.path, bytes);
  switch (kind) {
    case "image":
      wrap.appendChild(imagePreview(bytes, entry.path));
      return wrap;
    case "audio":
      wrap.appendChild(mediaPreview("audio", bytes, entry.path));
      return wrap;
    case "video":
      wrap.appendChild(mediaPreview("video", bytes, entry.path));
      return wrap;
    case "text":
      wrap.appendChild(textPreview(bytes));
      return wrap;
    case "pdf":
      wrap.appendChild(pdfPreview(bytes));
      return wrap;
    default: {
      const note = document.createElement("p");
      note.className = "archive-row-binary-note";
      note.textContent = `Binary content (${fmtBytes(bytes.byteLength)}). Click Save to write it to disk.`;
      wrap.appendChild(note);
      return wrap;
    }
  }
}

function imagePreview(bytes: Uint8Array, hint: string): HTMLElement {
  const mime = mimeFromPath(hint) ?? "image/*";
  const url = URL.createObjectURL(new Blob([bytes], { type: mime }));
  const img = document.createElement("img");
  img.className = "archive-image";
  img.alt = hint;
  img.draggable = false;
  img.src = url;
  // Revoke the object URL once the image has loaded, so we don't leak
  // them as the user opens many entries.
  img.addEventListener("load", () => URL.revokeObjectURL(url), { once: true });
  img.addEventListener("error", () => URL.revokeObjectURL(url), { once: true });
  return img;
}

function mediaPreview(
  tag: "audio" | "video",
  bytes: Uint8Array,
  hint: string,
): HTMLElement {
  const mime = mimeFromPath(hint) ?? `${tag}/*`;
  const url = URL.createObjectURL(new Blob([bytes], { type: mime }));
  const el = document.createElement(tag) as HTMLMediaElement;
  el.className = `archive-${tag}`;
  el.controls = true;
  el.src = url;
  return el;
}

function textPreview(bytes: Uint8Array): HTMLElement {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const pre = document.createElement("pre");
  pre.className = "archive-row-text";
  pre.textContent = text;
  return pre;
}

function pdfPreview(bytes: Uint8Array): HTMLElement {
  const url = URL.createObjectURL(new Blob([bytes], { type: "application/pdf" }));
  const iframe = document.createElement("iframe");
  iframe.className = "archive-pdf";
  iframe.src = url;
  iframe.setAttribute("sandbox", "");
  iframe.title = "Embedded PDF";
  return iframe;
}

type Kind = "image" | "audio" | "video" | "text" | "pdf" | "binary";

function inferKind(path: string, bytes: Uint8Array): Kind {
  const ext = (path.split(/[.]/).pop() ?? "").toLowerCase();
  if (["png", "jpg", "jpeg", "gif", "webp", "svg", "bmp", "avif"].includes(ext)) return "image";
  if (["mp3", "wav", "ogg", "opus", "flac", "m4a", "aac"].includes(ext)) return "audio";
  if (["mp4", "webm", "mov", "mkv", "avi"].includes(ext)) return "video";
  if (ext === "pdf") return "pdf";
  if (["txt", "md", "json", "csv", "yaml", "yml", "toml", "ini", "log", "html", "htm",
       "css", "js", "ts", "tsx", "jsx", "rs", "py", "go", "java", "kt", "swift",
       "sh", "bash", "zsh", "c", "cpp", "h", "hpp", "xml"].includes(ext)) {
    return "text";
  }
  // Last-resort sniff: if the bytes are almost entirely printable
  // ASCII / valid UTF-8 text, treat as text.
  if (looksLikeText(bytes)) return "text";
  return "binary";
}

function looksLikeText(bytes: Uint8Array): boolean {
  if (bytes.length === 0) return false;
  const sample = bytes.subarray(0, Math.min(bytes.length, 1024));
  let printable = 0;
  for (const b of sample) {
    if (b === 0) return false; // null byte → not text
    if (b === 9 || b === 10 || b === 13 || (b >= 0x20 && b < 0x7f) || b >= 0x80) {
      printable++;
    }
  }
  return printable / sample.length > 0.95;
}

function mimeFromPath(path: string): string | null {
  const ext = (path.split(/[.]/).pop() ?? "").toLowerCase();
  switch (ext) {
    case "png":
      return "image/png";
    case "jpg":
    case "jpeg":
      return "image/jpeg";
    case "gif":
      return "image/gif";
    case "webp":
      return "image/webp";
    case "svg":
      return "image/svg+xml";
    case "mp3":
      return "audio/mpeg";
    case "wav":
      return "audio/wav";
    case "ogg":
    case "opus":
      return "audio/ogg";
    case "mp4":
      return "video/mp4";
    case "webm":
      return "video/webm";
    case "pdf":
      return "application/pdf";
    default:
      return null;
  }
}

async function saveEntry(entry: InnerEntry, address: string): Promise<void> {
  try {
    const bytes = await extractEntry(address, entry.path);
    await writeBytesViaDialog(bytes, basename(entry.path));
  } catch (e) {
    alert(`Couldn't save: ${errMessage(e)}`);
  }
}

async function saveWholeArchive(address: string): Promise<void> {
  try {
    // The bytes are already cached server-side from the initial fetch;
    // hitting `fetchit://<addr>` reads them out without a re-fetch.
    const res = await fetch(`fetchit://${address}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const blob = await res.blob();
    const bytes = new Uint8Array(await blob.arrayBuffer());
    await writeBytesViaDialog(bytes, `${address.slice(0, 12)}.zip`);
  } catch (e) {
    alert(`Couldn't save archive: ${errMessage(e)}`);
  }
}

/** Use Tauri's plugin-dialog `save` + a Rust write command. The
 *  browser-native `<a download>` trick fails silently inside Tauri
 *  WebViews on Linux / Windows; this is the reliable path. */
async function writeBytesViaDialog(bytes: Uint8Array, defaultName: string): Promise<void> {
  const dest = await saveDialog({
    defaultPath: defaultName,
    title: "Save",
  });
  if (typeof dest !== "string") return; // user cancelled
  await invoke("save_bytes_to_path", { path: dest, data: Array.from(bytes) });
}

function basename(path: string): string {
  const last = path.split("/").pop() ?? path;
  return last || "file";
}

function errMessage(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  if (e && typeof e === "object" && "message" in e) {
    const m = (e as { message: unknown }).message;
    if (typeof m === "string") return m;
  }
  return String(e);
}
