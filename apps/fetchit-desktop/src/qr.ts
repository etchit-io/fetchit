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

// ── Exportable branded card ─────────────────────────────────────────
//
// The QR-share modal shows a stripped-down preview, but Save image /
// Copy image need to produce a fully branded artifact — the recipient
// needs to see "fetch>it" wordmark + the address + a scan-with hint,
// otherwise the QR is anonymous and the brand is lost.

const CARD_W = 720;
const CARD_PAD = 40;
const QR_BOX = CARD_W - CARD_PAD * 2;
const COPPER = "#c9732b";
const INK = "#1a1a1a";
const ASH = "#8a8a8a";
const WHITE = "#ffffff";
const FAMILY_SANS =
  "ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif";
const FAMILY_MONO =
  "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";

/** Abbreviated form of a 64-hex Autonomi address, suited for inline
 *  display next to a QR code (the full hex stays inside the QR + on the
 *  clipboard). Same 8+…+8 shape across desktop + mobile so a card and a
 *  bookmark / history row look related. */
export function abbreviateAddress(address: string): string {
  const hex = address.toLowerCase();
  if (hex.length <= 17) return hex;
  return `${hex.slice(0, 8)}…${hex.slice(-8)}`;
}

/** Build the full export-card SVG for an `autonomi://<hex>` address.
 *  Layout: fetch>it wordmark, QR with copper centre mark, optional
 *  serif-italic title, abbreviated address (single line), "scan with
 *  fetch>it on mobile · etchit.io" footer. Title is shown only when
 *  the caller has something meaningful (etch title, page <title>,
 *  filename) — recipients otherwise have no idea what they're opening. */
export function renderExportCardSvg(
  address: string,
  title?: string | null,
): SVGSVGElement {
  const hex = address.toLowerCase();
  const payload = `autonomi://${hex}`;
  const titleText = (title ?? "").trim();
  const showTitle = titleText.length > 0;
  // Cap title at ~40 chars so it fits one line at `titleSize` on a
  // 720-wide card. Past that the renderer can't keep it readable
  // without shrinking, which makes the layout feel uneven.
  const titleClamped = showTitle && titleText.length > 40
    ? `${titleText.slice(0, 39)}…`
    : titleText;

  const svgNS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(svgNS, "svg");
  svg.setAttribute("xmlns", svgNS);

  const wordmarkSize = 52;
  const titleSize = 26;
  const addrSize = 18;
  const footerSize = 18;
  const gap = 24;

  let y = CARD_PAD;
  const wordmarkY = y + wordmarkSize * 0.78;
  y += wordmarkSize + gap;
  const qrTop = y;
  y += QR_BOX + gap;
  let titleY = 0;
  if (showTitle) {
    titleY = y + titleSize * 0.78;
    y += titleSize + 10;
  }
  const addrLineY = y + addrSize * 0.78;
  y += addrSize + gap;
  const footerY = y + footerSize * 0.78;
  y += footerSize + CARD_PAD;
  const cardH = Math.ceil(y);

  svg.setAttribute("viewBox", `0 0 ${CARD_W} ${cardH}`);
  svg.setAttribute("width", String(CARD_W));
  svg.setAttribute("height", String(cardH));
  svg.setAttribute("shape-rendering", "crispEdges");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", `Share card for ${payload}`);

  const bg = document.createElementNS(svgNS, "rect");
  bg.setAttribute("x", "0");
  bg.setAttribute("y", "0");
  bg.setAttribute("width", String(CARD_W));
  bg.setAttribute("height", String(cardH));
  bg.setAttribute("fill", "#f5f2eb");
  svg.appendChild(bg);

  const word = (
    txt: string,
    color: string,
    anchor: "start" | "middle" | "end",
    x: number,
  ): SVGTextElement => {
    const t = document.createElementNS(svgNS, "text");
    t.setAttribute("x", String(x));
    t.setAttribute("y", String(wordmarkY));
    t.setAttribute("text-anchor", anchor);
    t.setAttribute("font-family", FAMILY_MONO);
    t.setAttribute("font-weight", "700");
    t.setAttribute("font-size", String(wordmarkSize));
    t.setAttribute("fill", color);
    t.textContent = txt;
    return t;
  };
  const chevOffset = wordmarkSize * 0.22;
  svg.appendChild(word("fetch", INK, "end", CARD_W / 2 - chevOffset));
  svg.appendChild(word(">", COPPER, "middle", CARD_W / 2));
  svg.appendChild(word("it", INK, "start", CARD_W / 2 + chevOffset));

  const qrPanel = document.createElementNS(svgNS, "rect");
  qrPanel.setAttribute("x", String(CARD_PAD));
  qrPanel.setAttribute("y", String(qrTop));
  qrPanel.setAttribute("width", String(QR_BOX));
  qrPanel.setAttribute("height", String(QR_BOX));
  qrPanel.setAttribute("fill", WHITE);
  qrPanel.setAttribute("stroke", "#e6e3da");
  qrPanel.setAttribute("stroke-width", "2");
  qrPanel.setAttribute("rx", "12");
  svg.appendChild(qrPanel);

  const qr = qrcode(0, "H");
  qr.addData(payload);
  qr.make();
  const moduleCount = qr.getModuleCount();
  const qrInsetPad = 16;
  const qrInner = QR_BOX - qrInsetPad * 2;
  const cellSize = qrInner / moduleCount;
  for (let row = 0; row < moduleCount; row++) {
    let runStart = -1;
    for (let col = 0; col <= moduleCount; col++) {
      const dark = col < moduleCount && qr.isDark(row, col);
      if (dark && runStart < 0) runStart = col;
      if (!dark && runStart >= 0) {
        const rect = document.createElementNS(svgNS, "rect");
        rect.setAttribute("x", String(CARD_PAD + qrInsetPad + runStart * cellSize));
        rect.setAttribute("y", String(qrTop + qrInsetPad + row * cellSize));
        rect.setAttribute("width", String((col - runStart) * cellSize));
        rect.setAttribute("height", String(cellSize));
        rect.setAttribute("fill", INK);
        svg.appendChild(rect);
        runStart = -1;
      }
    }
  }

  const qrCx = CARD_PAD + QR_BOX / 2;
  const qrCy = qrTop + QR_BOX / 2;
  const badgeSide = QR_BOX * 0.16;
  const badgeR = badgeSide * 0.18;
  const badge = document.createElementNS(svgNS, "rect");
  badge.setAttribute("x", String(qrCx - badgeSide / 2));
  badge.setAttribute("y", String(qrCy - badgeSide / 2));
  badge.setAttribute("width", String(badgeSide));
  badge.setAttribute("height", String(badgeSide));
  badge.setAttribute("rx", String(badgeR));
  badge.setAttribute("ry", String(badgeR));
  badge.setAttribute("fill", WHITE);
  badge.setAttribute("stroke", COPPER);
  badge.setAttribute("stroke-width", "3");
  svg.appendChild(badge);

  const chev = document.createElementNS(svgNS, "text");
  chev.setAttribute("x", String(qrCx));
  chev.setAttribute("y", String(qrCy));
  chev.setAttribute("text-anchor", "middle");
  chev.setAttribute("dominant-baseline", "central");
  chev.setAttribute("font-family", FAMILY_MONO);
  chev.setAttribute("font-weight", "700");
  chev.setAttribute("font-size", String(badgeSide * 0.78));
  chev.setAttribute("fill", COPPER);
  chev.textContent = ">";
  svg.appendChild(chev);

  if (showTitle) {
    const titleEl = document.createElementNS(svgNS, "text");
    titleEl.setAttribute("x", String(CARD_W / 2));
    titleEl.setAttribute("y", String(titleY));
    titleEl.setAttribute("text-anchor", "middle");
    titleEl.setAttribute("font-family", "'Instrument Serif', serif");
    titleEl.setAttribute("font-style", "italic");
    titleEl.setAttribute("font-size", String(titleSize));
    titleEl.setAttribute("fill", INK);
    titleEl.textContent = titleClamped;
    svg.appendChild(titleEl);
  }

  const addrText = document.createElementNS(svgNS, "text");
  addrText.setAttribute("x", String(CARD_W / 2));
  addrText.setAttribute("y", String(addrLineY));
  addrText.setAttribute("text-anchor", "middle");
  addrText.setAttribute("font-family", FAMILY_MONO);
  addrText.setAttribute("font-size", String(addrSize));
  addrText.setAttribute("fill", ASH);
  addrText.textContent = abbreviateAddress(hex);
  svg.appendChild(addrText);

  const footer = document.createElementNS(svgNS, "text");
  footer.setAttribute("x", String(CARD_W / 2));
  footer.setAttribute("y", String(footerY));
  footer.setAttribute("text-anchor", "middle");
  footer.setAttribute("font-family", FAMILY_SANS);
  footer.setAttribute("font-size", String(footerSize));
  footer.setAttribute("font-weight", "600");
  footer.setAttribute("fill", INK);
  const seg = (txt: string, color: string): SVGTSpanElement => {
    const s = document.createElementNS(svgNS, "tspan");
    s.setAttribute("fill", color);
    s.textContent = txt;
    return s;
  };
  footer.appendChild(seg("scan with fetch", INK));
  footer.appendChild(seg(">", COPPER));
  footer.appendChild(seg("it on mobile · ", INK));
  footer.appendChild(seg("etchit.io", COPPER));
  svg.appendChild(footer);

  return svg;
}
