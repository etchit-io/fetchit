import { describe, it, expect } from "vitest";
import {
  ALLOWED_ATTACHMENT_MIMES,
  MAX_ATTACHMENT_BYTES,
  sniffRasterMime,
  validateImageBytes,
  bytesToB64,
  b64ToBytes,
  attachmentDataUrl,
  fileToAttachment,
} from "./imageAttach";

// Minimal valid magic-byte headers for each raster format. Only the
// signature matters to the sniffer; the trailing bytes are filler.
const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0]);
const JPEG = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0, 0, 0, 0]);
const GIF = new Uint8Array([0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0, 0]);
// "RIFF" .... "WEBP"
const WEBP = new Uint8Array([
  0x52, 0x49, 0x46, 0x46, 0x10, 0, 0, 0, 0x57, 0x45, 0x42, 0x50, 0, 0, 0, 0,
]);
const SVG = new Uint8Array([...new TextEncoder().encode("<svg xmlns='...'></svg>")]);
const HTML = new Uint8Array([...new TextEncoder().encode("<!DOCTYPE html><script>")]);

describe("sniffRasterMime", () => {
  it("detects each allowed raster format from its magic bytes", () => {
    expect(sniffRasterMime(PNG)).toBe("image/png");
    expect(sniffRasterMime(JPEG)).toBe("image/jpeg");
    expect(sniffRasterMime(GIF)).toBe("image/gif");
    expect(sniffRasterMime(WEBP)).toBe("image/webp");
  });

  it("returns null for SVG (the XSS vector) and HTML", () => {
    expect(sniffRasterMime(SVG)).toBeNull();
    expect(sniffRasterMime(HTML)).toBeNull();
  });

  it("returns null for arbitrary / too-short bytes", () => {
    expect(sniffRasterMime(new Uint8Array([1, 2, 3]))).toBeNull();
    expect(sniffRasterMime(new Uint8Array([]))).toBeNull();
  });

  it("every sniffed mime is in the allowlist", () => {
    for (const sig of [PNG, JPEG, GIF, WEBP]) {
      const mime = sniffRasterMime(sig);
      expect(mime).not.toBeNull();
      expect(ALLOWED_ATTACHMENT_MIMES).toContain(mime as string);
    }
  });
});

describe("validateImageBytes", () => {
  it("accepts a valid raster image under the cap", () => {
    const r = validateImageBytes(PNG);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.mime).toBe("image/png");
  });

  it("rejects non-raster content (svg) as a disallowed type", () => {
    const r = validateImageBytes(SVG);
    expect(r.ok).toBe(false);
  });

  it("rejects bytes over the size cap before anything else", () => {
    // A valid PNG header but oversize body must still be rejected.
    const big = new Uint8Array(MAX_ATTACHMENT_BYTES + 1);
    big.set(PNG.slice(0, 8));
    const r = validateImageBytes(big);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/too large|256/i);
  });

  it("accepts exactly the cap", () => {
    const atCap = new Uint8Array(MAX_ATTACHMENT_BYTES);
    atCap.set(PNG.slice(0, 8));
    expect(validateImageBytes(atCap).ok).toBe(true);
  });
});

describe("base64 round trip", () => {
  it("matches a known vector and round-trips arbitrary bytes", () => {
    expect(bytesToB64(new TextEncoder().encode("hello"))).toBe("aGVsbG8=");
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 255, 128, 64]);
    expect([...b64ToBytes(bytesToB64(bytes))]).toEqual([...bytes]);
  });

  it("round-trips a multi-kilobyte buffer without stack overflow", () => {
    const bytes = new Uint8Array(100_000).map((_, i) => i % 256);
    expect([...b64ToBytes(bytesToB64(bytes))]).toEqual([...bytes]);
  });
});

describe("attachmentDataUrl", () => {
  it("formats a data: URL with the declared mime", () => {
    expect(
      attachmentDataUrl({ mime: "image/png", width: 1, height: 1, bytes_b64: "AAA=" }),
    ).toBe("data:image/png;base64,AAA=");
  });
});

describe("fileToAttachment", () => {
  const stubDims = () => Promise.resolve({ width: 12, height: 8 });

  it("builds a validated Attachment from a raster file", async () => {
    const file = new File([PNG], "x.png", { type: "image/png" });
    const att = await fileToAttachment(file, stubDims);
    expect(att.mime).toBe("image/png");
    expect(att.width).toBe(12);
    expect(att.height).toBe(8);
    expect([...b64ToBytes(att.bytes_b64)]).toEqual([...PNG]);
  });

  it("rejects an SVG file regardless of its declared MIME", async () => {
    // Declared image/png, but the bytes are SVG — the sniff must win.
    const file = new File([SVG], "x.png", { type: "image/png" });
    await expect(fileToAttachment(file, stubDims)).rejects.toThrow();
  });

  it("rejects an oversize file", async () => {
    const big = new Uint8Array(MAX_ATTACHMENT_BYTES + 1);
    big.set(PNG.slice(0, 8));
    const file = new File([big], "big.png", { type: "image/png" });
    await expect(fileToAttachment(file, stubDims)).rejects.toThrow();
  });
});
