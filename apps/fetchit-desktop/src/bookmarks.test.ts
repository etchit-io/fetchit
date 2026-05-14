import { describe, expect, it } from "vitest";
import { deriveLabel } from "./bookmarks";

const ADDR = "0123456789abcdef".repeat(4);

describe("deriveLabel", () => {
  it("falls back to truncated address when no rendition", () => {
    expect(deriveLabel(null, ADDR)).toBe(`${ADDR.slice(0, 8)}…${ADDR.slice(-4)}`);
    expect(deriveLabel(undefined, ADDR)).toBe(`${ADDR.slice(0, 8)}…${ADDR.slice(-4)}`);
  });

  it("uses etchit envelope title", () => {
    expect(deriveLabel(
      { kind: "etchitEnvelope", title: "  My Doc  ", content: "", language: null },
      ADDR,
    )).toBe("My Doc");
  });

  it("falls back when envelope has no title", () => {
    expect(deriveLabel(
      { kind: "etchitEnvelope", title: "", content: "x", language: null },
      ADDR,
    )).toBe(`${ADDR.slice(0, 8)}…${ADDR.slice(-4)}`);
  });

  it("extracts <title> from html body", () => {
    expect(deriveLabel(
      { kind: "html", body: "<html><head><title>Page Title</title></head></html>" },
      ADDR,
    )).toBe("Page Title");
  });

  it("html with no title falls back to truncated address", () => {
    expect(deriveLabel(
      { kind: "html", body: "<html><body>hi</body></html>" },
      ADDR,
    )).toBe(`${ADDR.slice(0, 8)}…${ADDR.slice(-4)}`);
  });

  it("html title is trimmed and capped at 80 chars", () => {
    const long = "x".repeat(120);
    const label = deriveLabel(
      { kind: "html", body: `<title>  ${long}  </title>` },
      ADDR,
    );
    expect(label.length).toBe(80);
    expect(label.startsWith("x")).toBe(true);
  });

  it("non-html rendition (image / json / etc) falls back to truncated address", () => {
    expect(deriveLabel(
      { kind: "image", mime: "image/png", byteLen: 100 },
      ADDR,
    )).toBe(`${ADDR.slice(0, 8)}…${ADDR.slice(-4)}`);
    expect(deriveLabel(
      { kind: "json", pretty: "{}" },
      ADDR,
    )).toBe(`${ADDR.slice(0, 8)}…${ADDR.slice(-4)}`);
  });
});
