import { describe, expect, it } from "vitest";
import { isSelfContained } from "./selfContained";

const ADDR = "a".repeat(64);

describe("isSelfContained", () => {
  it("returns true for a bare doc with no external refs", () => {
    expect(isSelfContained("<!doctype html><h1>hi</h1>")).toBe(true);
  });

  it("returns true for inline data URIs", () => {
    expect(
      isSelfContained(`<!doctype html><img src="data:image/png;base64,AAAA">`),
    ).toBe(true);
  });

  it("returns true for autonomi:// references (internal)", () => {
    expect(
      isSelfContained(`<!doctype html><img src="autonomi://${ADDR}">`),
    ).toBe(true);
  });

  it("returns true for relative and root-relative references", () => {
    expect(
      isSelfContained(
        `<!doctype html><img src="/photo.png"><script src="./app.js"></script>`,
      ),
    ).toBe(true);
  });

  it("returns false on an external <img src>", () => {
    expect(
      isSelfContained(
        `<!doctype html><img src="https://external.com/x.png">`,
      ),
    ).toBe(false);
  });

  it("returns false on an external <script src>", () => {
    expect(
      isSelfContained(
        `<!doctype html><script src="https://cdn.example/lib.js"></script>`,
      ),
    ).toBe(false);
  });

  it("returns false on an external <link href> (any rel)", () => {
    expect(
      isSelfContained(
        `<!doctype html><link rel="stylesheet" href="https://fonts.example/x.css">`,
      ),
    ).toBe(false);
  });

  it("returns false on an external srcset entry", () => {
    expect(
      isSelfContained(
        `<!doctype html><img srcset="https://cdn.example/1x.png 1x, /local-2x.png 2x">`,
      ),
    ).toBe(false);
  });

  it("returns false on a CSS url() inside <style>", () => {
    expect(
      isSelfContained(
        `<!doctype html><style>body { background: url(https://example.com/bg.png); }</style>`,
      ),
    ).toBe(false);
  });

  it("returns false on a CSS url() inside an inline style attribute", () => {
    expect(
      isSelfContained(
        `<!doctype html><div style="background:url('https://example.com/bg.png')">x</div>`,
      ),
    ).toBe(false);
  });

  it("ignores <a href> — anchors are navigation, not subresources", () => {
    expect(
      isSelfContained(
        `<!doctype html><a href="https://external.com/page">link</a>`,
      ),
    ).toBe(true);
  });

  it("treats http:// the same as https://", () => {
    expect(
      isSelfContained(
        `<!doctype html><img src="http://insecure.example/x.png">`,
      ),
    ).toBe(false);
  });
});
