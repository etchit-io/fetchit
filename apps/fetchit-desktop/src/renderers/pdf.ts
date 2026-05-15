import type { Rendition } from "../types";
import { el, fmtBytes } from "../format";

// pdf.js is heavy (~800 KB) — load it lazily on first PDF render so the
// initial bundle stays lean. The worker URL is asset-resolved by Vite.
type PdfjsModule = typeof import("pdfjs-dist");
let pdfjsPromise: Promise<PdfjsModule> | null = null;

async function getPdfJs(): Promise<PdfjsModule> {
  if (pdfjsPromise) return pdfjsPromise;
  pdfjsPromise = (async () => {
    const pdfjs = await import("pdfjs-dist");
    const workerUrl = (await import("pdfjs-dist/build/pdf.worker.min.mjs?url")).default;
    pdfjs.GlobalWorkerOptions.workerSrc = workerUrl;
    return pdfjs;
  })();
  return pdfjsPromise;
}

export function renderPdf(
  r: Extract<Rendition, { kind: "pdf" }>,
  into: HTMLElement,
  src: string,
): void {
  const root = document.createElement("div");
  root.className = "pdf-viewer";

  const toolbar = document.createElement("div");
  toolbar.className = "pdf-toolbar";
  const pageIndicator = document.createElement("span");
  pageIndicator.className = "pdf-status";
  pageIndicator.textContent = `loading PDF · ${fmtBytes(r.byteLen)}`;
  toolbar.appendChild(pageIndicator);

  const pages = document.createElement("div");
  pages.className = "pdf-pages";

  root.append(toolbar, pages);
  into.appendChild(root);

  void load(src, pages, pageIndicator).catch((err: unknown) => {
    const msg = err instanceof Error ? err.message : String(err);
    pages.replaceChildren(el("pre", `[pdf failed: ${msg}]`));
    pageIndicator.textContent = "—";
  });
}

async function load(src: string, pages: HTMLElement, indicator: HTMLElement): Promise<void> {
  const pdfjs = await getPdfJs();
  const task = pdfjs.getDocument({ url: src });
  const doc = await task.promise;
  const total = doc.numPages;
  indicator.textContent = `1 / ${total}`;

  // Compute target width from the pages container — fall back to a reasonable
  // default if it isn't laid out yet.
  const containerWidth = pages.clientWidth || 800;
  const targetWidth = Math.max(320, containerWidth - 24);

  // Render pages sequentially. Sequential is fine — pdf.js streams chunks via
  // Range requests, and rendering early pages first gives the user something
  // to read while later pages are still parsing.
  for (let i = 1; i <= total; i++) {
    const page = await doc.getPage(i);
    const baseViewport = page.getViewport({ scale: 1 });
    const scale = targetWidth / baseViewport.width;
    const viewport = page.getViewport({ scale });

    const canvas = document.createElement("canvas");
    canvas.className = "pdf-page";
    canvas.dataset.pageNumber = String(i);
    // Match device pixel ratio so text stays crisp on hi-dpi displays.
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.floor(viewport.width * dpr);
    canvas.height = Math.floor(viewport.height * dpr);
    canvas.style.width = `${viewport.width}px`;
    canvas.style.height = `${viewport.height}px`;
    pages.appendChild(canvas);

    const ctx = canvas.getContext("2d");
    if (!ctx) continue;
    if (dpr !== 1) ctx.scale(dpr, dpr);
    await page.render({ canvas, canvasContext: ctx, viewport }).promise;
  }

  bindPageIndicator(pages, indicator, total);
}

// Update the "X / N" indicator as the user scrolls — the most-visible canvas
// wins. Uses IntersectionObserver against the pages container.
function bindPageIndicator(pages: HTMLElement, indicator: HTMLElement, total: number): void {
  const observer = new IntersectionObserver(
    (entries) => {
      let best: { ratio: number; page: number } | null = null;
      for (const e of entries) {
        if (!e.isIntersecting) continue;
        const n = Number((e.target as HTMLElement).dataset.pageNumber);
        if (!Number.isFinite(n)) continue;
        if (!best || e.intersectionRatio > best.ratio) best = { ratio: e.intersectionRatio, page: n };
      }
      if (best) indicator.textContent = `${best.page} / ${total}`;
    },
    { root: pages, threshold: [0.25, 0.5, 0.75] },
  );
  for (const c of pages.querySelectorAll<HTMLCanvasElement>(".pdf-page")) observer.observe(c);
}
