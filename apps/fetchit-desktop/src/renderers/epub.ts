// EPUB renderer.
//
// EPUB is a ZIP carrying an `application/epub+zip` mimetype plus a
// `META-INF/container.xml` pointing to the OPF manifest, which in turn
// lists the spine (chapters in reading order). Core classifies it as
// `Archive`; `dispatch.ts` looks at the entry list to decide whether to
// hand it here instead of to `renderArchive`.
//
// We fetch the raw EPUB bytes over `autonomi://<addr>`, parse the zip
// with `fflate`, then render one chapter at a time in a sandboxed
// iframe. Internal references (images, CSS) are inlined as `data:` URLs
// because the iframe is null-origin and can't reach the rest of the
// archive on its own. The same `htmlRewriter` we use for stand-alone
// HTML pages handles the CSP / sandbox neutering.

import { unzipSync, strFromU8 } from "fflate";
import type { Rendition } from "../types";
import { rewriteHtml } from "./htmlRewriter";
import { mediaBase } from "../mediaUrl";

const SANDBOX = "allow-scripts allow-forms";

export interface SpineItem {
  /** Manifest id (kept for debugging). */
  id: string;
  /** Absolute path inside the zip (resolved against the OPF directory). */
  path: string;
  /** Display title — from the OPF nav doc if available, otherwise the path tail. */
  title: string;
}

export interface Book {
  title: string;
  spine: SpineItem[];
  /** Zip entries, keyed by absolute path within the archive. */
  files: Record<string, Uint8Array>;
}

export function renderEpub(
  _r: Extract<Rendition, { kind: "archive" }>,
  into: HTMLElement,
  address: string,
): void {
  const wrap = document.createElement("div");
  wrap.className = "rendered-epub";
  wrap.textContent = "loading book…";
  into.appendChild(wrap);

  void loadAndRender(address).then(
    (book) => mountReader(wrap, book, address),
    (err: unknown) => {
      wrap.textContent = "";
      const e = document.createElement("p");
      e.className = "epub-error";
      e.textContent = `couldn't read EPUB: ${(err as Error).message ?? String(err)}`;
      wrap.appendChild(e);
    },
  );
}

async function loadAndRender(address: string): Promise<Book> {
  const res = await fetch(`autonomi://${address}`);
  if (!res.ok) throw new Error(`fetch failed: HTTP ${res.status}`);
  const bytes = new Uint8Array(await res.arrayBuffer());
  const files = unzipSync(bytes);
  return parseBook(files);
}

export function parseBook(files: Record<string, Uint8Array>): Book {
  const containerXml = readText(files, "META-INF/container.xml");
  if (!containerXml) throw new Error("missing META-INF/container.xml");
  const opfPath = extractAttr(containerXml, "rootfile", "full-path");
  if (!opfPath) throw new Error("META-INF/container.xml: no rootfile");
  const opf = readText(files, opfPath);
  if (!opf) throw new Error(`OPF missing at ${opfPath}`);

  const opfDir = opfPath.includes("/") ? opfPath.slice(0, opfPath.lastIndexOf("/") + 1) : "";

  // Title — first <dc:title> wins; the spec allows multiple, we don't care.
  // Treat empty-string titles the same as missing: fall back to "Untitled".
  const titleRaw = stripTags(matchTag(opf, "dc:title") ?? matchTag(opf, "title") ?? "");
  const title = titleRaw || "Untitled";

  // Manifest: id → href (absolute path).
  const manifest = new Map<string, string>();
  for (const item of extractAll(opf, "item")) {
    const id = extractAttr(item, "item", "id");
    const href = extractAttr(item, "item", "href");
    if (id && href) manifest.set(id, normalize(opfDir + decodeURI(href)));
  }

  // Spine: ordered list of idrefs that resolve through the manifest.
  const spine: SpineItem[] = [];
  for (const ref of extractAll(opf, "itemref")) {
    const idref = extractAttr(ref, "itemref", "idref");
    if (!idref) continue;
    const path = manifest.get(idref);
    if (!path) continue;
    spine.push({
      id: idref,
      path,
      title: prettyChapterTitle(path),
    });
  }
  if (spine.length === 0) throw new Error("OPF has no spine items");

  return { title, spine, files };
}

function mountReader(into: HTMLElement, book: Book, _address: string): void {
  into.replaceChildren();

  const header = document.createElement("header");
  header.className = "epub-header";
  const titleEl = document.createElement("h2");
  titleEl.className = "epub-title";
  titleEl.textContent = book.title;
  header.appendChild(titleEl);
  into.appendChild(header);

  const layout = document.createElement("div");
  layout.className = "epub-layout";
  into.appendChild(layout);

  const toc = document.createElement("nav");
  toc.className = "epub-toc";
  toc.setAttribute("aria-label", "Chapters");
  layout.appendChild(toc);

  const content = document.createElement("div");
  content.className = "epub-content";
  layout.appendChild(content);

  const iframe = document.createElement("iframe");
  iframe.title = `${book.title} — chapter`;
  iframe.setAttribute("referrerpolicy", "no-referrer");
  iframe.setAttribute("sandbox", SANDBOX);
  iframe.className = "epub-frame";
  content.appendChild(iframe);

  const nav = document.createElement("div");
  nav.className = "epub-nav";
  const prev = document.createElement("button");
  prev.textContent = "← Prev";
  prev.type = "button";
  const next = document.createElement("button");
  next.textContent = "Next →";
  next.type = "button";
  const pos = document.createElement("span");
  pos.className = "epub-pos";
  nav.append(prev, pos, next);
  content.appendChild(nav);

  let current = 0;
  const tocButtons: HTMLButtonElement[] = [];

  for (const [i, item] of book.spine.entries()) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = item.title;
    btn.className = "epub-toc-item";
    btn.addEventListener("click", () => goTo(i));
    toc.appendChild(btn);
    tocButtons.push(btn);
  }

  function goTo(i: number): void {
    if (i < 0 || i >= book.spine.length) return;
    current = i;
    for (const [idx, b] of tocButtons.entries()) {
      b.classList.toggle("is-active", idx === current);
    }
    pos.textContent = `${current + 1} / ${book.spine.length}`;
    prev.disabled = current === 0;
    next.disabled = current === book.spine.length - 1;
    const item = book.spine[current];
    const xhtml = readText(book.files, item.path);
    if (!xhtml) {
      iframe.srcdoc = `<p>chapter file missing: ${escapeHtml(item.path)}</p>`;
      return;
    }
    const inlined = inlineResources(xhtml, item.path, book.files);
    // We don't actually have a sensible "address" for an EPUB chapter
    // (the chapter is internal to a zip, not a separate Autonomi
    // address). Pass the address-less synthetic id so the rewriter's
    // base/CSP construction still works.
    iframe.srcdoc = rewriteHtml(inlined, "0".repeat(64), mediaBase());
    content.scrollTop = 0;
  }

  prev.addEventListener("click", () => goTo(current - 1));
  next.addEventListener("click", () => goTo(current + 1));

  goTo(0);
}

// ── EPUB → inline-resource helpers ─────────────────────────────────────

export function inlineResources(
  xhtml: string,
  chapterPath: string,
  files: Record<string, Uint8Array>,
): string {
  const chapterDir = chapterPath.includes("/")
    ? chapterPath.slice(0, chapterPath.lastIndexOf("/") + 1)
    : "";

  const resolve = (href: string): string | null => {
    if (!href || /^(?:https?:|data:|mailto:|tel:|autonomi:|fetchit:)/i.test(href)) return null;
    if (href.startsWith("#")) return null;
    const path = normalize(chapterDir + decodeURI(href.split("#")[0]).replace(/^\.\//, ""));
    const data = files[path];
    if (!data) return null;
    const mime = guessMime(path);
    return `data:${mime};base64,${base64(data)}`;
  };

  // Rewrite src/href attributes on img / image / link / source / video / audio.
  return xhtml.replace(
    /\b(src|href|xlink:href)\s*=\s*("([^"]*)"|'([^']*)')/gi,
    (m, attr: string, _q, dq: string | undefined, sq: string | undefined) => {
      const value = dq ?? sq ?? "";
      const rewritten = resolve(value);
      if (!rewritten) return m;
      return `${attr}="${rewritten}"`;
    },
  );
}

// ── tiny parsing helpers ───────────────────────────────────────────────

function readText(files: Record<string, Uint8Array>, path: string): string | null {
  const data = files[path];
  return data ? strFromU8(data) : null;
}

function matchTag(xml: string, tag: string): string | null {
  const re = new RegExp(`<${escapeReg(tag)}\\b[^>]*>([\\s\\S]*?)<\\/${escapeReg(tag)}\\s*>`, "i");
  return xml.match(re)?.[1]?.trim() ?? null;
}

function extractAll(xml: string, tag: string): string[] {
  const re = new RegExp(`<${escapeReg(tag)}\\b[^>]*/?>`, "gi");
  return xml.match(re) ?? [];
}

function extractAttr(xml: string, _tag: string, attr: string): string | null {
  const re = new RegExp(`\\b${escapeReg(attr)}\\s*=\\s*("([^"]*)"|'([^']*)')`, "i");
  const m = xml.match(re);
  return m ? (m[2] ?? m[3] ?? null) : null;
}

function stripTags(s: string): string {
  return s.replace(/<[^>]+>/g, "").trim();
}

function escapeReg(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch] ?? ch);
}

function normalize(path: string): string {
  const parts: string[] = [];
  for (const seg of path.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") parts.pop();
    else parts.push(seg);
  }
  return parts.join("/");
}

function prettyChapterTitle(path: string): string {
  const tail = path.split("/").pop() ?? path;
  return tail.replace(/\.x?html?$/i, "").replace(/[-_]/g, " ").trim() || tail;
}

const MIME_BY_EXT: Record<string, string> = {
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".png": "image/png",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".svg": "image/svg+xml",
  ".css": "text/css",
  ".html": "text/html",
  ".xhtml": "application/xhtml+xml",
  ".otf": "font/otf",
  ".ttf": "font/ttf",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
};

function guessMime(path: string): string {
  const lower = path.toLowerCase();
  const dot = lower.lastIndexOf(".");
  if (dot < 0) return "application/octet-stream";
  return MIME_BY_EXT[lower.slice(dot)] ?? "application/octet-stream";
}

function base64(bytes: Uint8Array): string {
  // Stream the bytes through chunks to dodge the call-stack limit on big
  // images (~125 KB worth at a time is well under any engine's arg cap).
  let s = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    s += String.fromCharCode(...bytes.subarray(i, Math.min(i + CHUNK, bytes.length)));
  }
  return btoa(s);
}

// ── EPUB-shape detection (used by dispatch.ts) ─────────────────────────

/**
 * Heuristic: does this Archive look like an EPUB? An EPUB has the
 * mandatory `META-INF/container.xml`. We don't check for the `mimetype`
 * file (it's not always re-emitted by sloppy writers).
 */
export function archiveIsEpub(entries: { path: string }[]): boolean {
  return entries.some((e) => e.path === "META-INF/container.xml");
}
