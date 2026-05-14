// QR generation. Wraps qrcode-generator's matrix output in inline SVG so the
// result is a self-contained vector — no canvas, no raster — that scales
// cleanly at any size and is trivial to copy via a serialized blob.
//
// We target QR version 0 ("auto" — the library picks the smallest version
// that fits the payload) and error-correction level "M" (~15%): for a
// 64-hex-plus-`autonomi://` payload (~75 chars) version 4 at level M
// suffices, leaving plenty of headroom against minor visual damage.

import qrcode from "qrcode-generator";

export type QrErrorCorrection = "L" | "M" | "Q" | "H";

export interface QrSvgOptions {
  /** Per-module pixel size. The SVG sets viewBox so this is more like a hint. */
  cellSize?: number;
  /** Margin in modules around the matrix (the "quiet zone"). 4 is QR-spec-correct. */
  margin?: number;
  /** CSS color of the dark modules. Defaults to currentColor so the parent's `color` controls it. */
  foreground?: string;
  /** CSS color of the light modules. Defaults to transparent. */
  background?: string;
  /**
   * Error-correction level. Higher levels survive more occlusion at the cost
   * of denser QR matrices. Default `M` (~15%) suits short payloads; bump to
   * `H` (~30%) when overlaying a center logo.
   */
  errorCorrectionLevel?: QrErrorCorrection;
  /**
   * Embed a short text mark in the QR's center (a "branded QR"). The library
   * draws a white square big enough for the glyph and stamps the text on top.
   * Only safe with `errorCorrectionLevel: "H"` for non-trivial payloads.
   */
  centerLogo?: {
    /** The text (1-3 glyphs works best — "&gt;" / "&gt;<" / monogram). */
    text: string;
    /** Foreground color of the logo. Default: matches the QR foreground. */
    color?: string;
    /**
     * Logo box size as a fraction of the QR canvas. Default 0.18 (≈18%) —
     * pairs well with EC level H and a 64-hex payload.
     */
    sizeRatio?: number;
  };
}

export function renderQrSvg(text: string, opts: QrSvgOptions = {}): SVGSVGElement {
  const cellSize = opts.cellSize ?? 8;
  const margin = opts.margin ?? 4;
  const fg = opts.foreground ?? "currentColor";
  const bg = opts.background ?? "transparent";
  const ec = opts.errorCorrectionLevel ?? "M";

  const qr = qrcode(0, ec);
  qr.addData(text);
  qr.make();

  const moduleCount = qr.getModuleCount();
  const size = (moduleCount + margin * 2) * cellSize;

  const svgNS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(svgNS, "svg");
  svg.setAttribute("xmlns", svgNS);
  svg.setAttribute("viewBox", `0 0 ${size} ${size}`);
  svg.setAttribute("width", String(size));
  svg.setAttribute("height", String(size));
  svg.setAttribute("shape-rendering", "crispEdges");
  svg.setAttribute("aria-label", "QR code");
  svg.setAttribute("role", "img");

  if (bg !== "transparent") {
    const rect = document.createElementNS(svgNS, "rect");
    rect.setAttribute("width", String(size));
    rect.setAttribute("height", String(size));
    rect.setAttribute("fill", bg);
    svg.appendChild(rect);
  }

  // Walk the matrix; combine consecutive dark cells in the same row into a
  // single `<rect>` to keep the DOM tight. A 33×33 matrix becomes hundreds of
  // rects instead of ~1100, with no visual difference.
  for (let y = 0; y < moduleCount; y++) {
    let runStart = -1;
    for (let x = 0; x <= moduleCount; x++) {
      const dark = x < moduleCount && qr.isDark(y, x);
      if (dark && runStart < 0) runStart = x;
      if (!dark && runStart >= 0) {
        const rect = document.createElementNS(svgNS, "rect");
        rect.setAttribute("x", String((runStart + margin) * cellSize));
        rect.setAttribute("y", String((y + margin) * cellSize));
        rect.setAttribute("width", String((x - runStart) * cellSize));
        rect.setAttribute("height", String(cellSize));
        rect.setAttribute("fill", fg);
        svg.appendChild(rect);
        runStart = -1;
      }
    }
  }

  // Optional center brand. White panel covers a small fraction of the matrix;
  // EC level H lets the scanner reconstruct the obscured cells. Stamp the text
  // on top in the same `currentColor`-aware fill the modules use.
  if (opts.centerLogo) {
    const ratio = opts.centerLogo.sizeRatio ?? 0.18;
    const boxSide = Math.round(size * ratio);
    const box = Math.round(boxSide);
    const cx = size / 2;
    const cy = size / 2;
    const pad = Math.round(box * 0.08);

    const panel = document.createElementNS(svgNS, "rect");
    panel.setAttribute("x", String(cx - box / 2));
    panel.setAttribute("y", String(cy - box / 2));
    panel.setAttribute("width", String(box));
    panel.setAttribute("height", String(box));
    panel.setAttribute("rx", String(Math.round(box * 0.12)));
    panel.setAttribute("fill", "#ffffff");
    svg.appendChild(panel);

    const label = document.createElementNS(svgNS, "text");
    label.setAttribute("x", String(cx));
    label.setAttribute("y", String(cy));
    label.setAttribute("text-anchor", "middle");
    label.setAttribute("dominant-baseline", "central");
    label.setAttribute("font-family", "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace");
    label.setAttribute("font-weight", "700");
    label.setAttribute("font-size", String(box - pad * 2));
    label.setAttribute("fill", opts.centerLogo.color ?? fg);
    label.textContent = opts.centerLogo.text;
    svg.appendChild(label);
  }
  return svg;
}

/** Serialize an SVG element to a UTF-8 string (for clipboard / blob). */
export function serializeSvg(svg: SVGSVGElement): string {
  return new XMLSerializer().serializeToString(svg);
}
