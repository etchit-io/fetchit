import { describe, expect, it } from "vitest";
import { renderQrSvg, serializeSvg } from "./qr";

describe("renderQrSvg", () => {
  it("returns an svg element with a viewBox", () => {
    const svg = renderQrSvg("autonomi://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd");
    expect(svg.tagName.toLowerCase()).toBe("svg");
    expect(svg.getAttribute("viewBox")).toMatch(/^0 0 \d+ \d+$/);
    expect(svg.getAttribute("role")).toBe("img");
  });

  it("emits at least one rect for a non-empty payload", () => {
    const svg = renderQrSvg("hello");
    expect(svg.querySelectorAll("rect").length).toBeGreaterThan(0);
  });

  it("scales with cellSize", () => {
    const small = renderQrSvg("hello", { cellSize: 4 });
    const big = renderQrSvg("hello", { cellSize: 16 });
    const smallSize = Number(small.getAttribute("width"));
    const bigSize = Number(big.getAttribute("width"));
    expect(bigSize).toBeGreaterThan(smallSize);
    expect(bigSize / smallSize).toBe(4);
  });

  it("paints a background rect when one is requested", () => {
    const transparent = renderQrSvg("hello");
    const filled = renderQrSvg("hello", { background: "#fff" });
    // The first child of `filled` should be the bg rect (transparent has none).
    expect(filled.firstChild).not.toBeNull();
    const firstWidth = (filled.firstChild as Element).getAttribute("width");
    expect(firstWidth).toBe(filled.getAttribute("width"));
    // The transparent variant's first child is a module rect, narrower than the whole canvas.
    expect((transparent.firstChild as Element).getAttribute("width")).not.toBe(
      transparent.getAttribute("width"),
    );
  });

  it("uses currentColor for foreground by default so CSS `color` drives the QR", () => {
    const svg = renderQrSvg("hello");
    const rect = svg.querySelector("rect");
    expect(rect?.getAttribute("fill")).toBe("currentColor");
  });

  it("serializeSvg round-trips through XMLSerializer", () => {
    const svg = renderQrSvg("hello");
    const s = serializeSvg(svg);
    expect(s).toContain("<svg");
    expect(s).toContain("</svg>");
    expect(s).toContain("viewBox");
  });

  it("embeds a center logo when requested (white panel + text)", () => {
    const svg = renderQrSvg(
      "autonomi://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
      {
        errorCorrectionLevel: "H",
        centerLogo: { text: ">", sizeRatio: 0.18 },
      },
    );
    const text = svg.querySelector("text");
    expect(text).not.toBeNull();
    expect(text?.textContent).toBe(">");
    // Panel is the white rect added late; check at least one rect has fill="#ffffff"
    const whiteRects = Array.from(svg.querySelectorAll("rect")).filter(
      (r) => r.getAttribute("fill") === "#ffffff",
    );
    expect(whiteRects.length).toBe(1);
  });

  it("supports H error correction (denser matrix than M for same payload)", () => {
    const m = renderQrSvg("autonomi://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd", { errorCorrectionLevel: "M" });
    const h = renderQrSvg("autonomi://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd", { errorCorrectionLevel: "H" });
    // viewBox stays the same shape; module count grows under H, so the SVG
    // canvas scales up too (cellSize is constant).
    const mSize = Number(m.getAttribute("width"));
    const hSize = Number(h.getAttribute("width"));
    expect(hSize).toBeGreaterThanOrEqual(mSize);
  });
});
