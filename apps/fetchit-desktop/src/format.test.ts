import { describe, expect, it } from "vitest";
import { el, fmtBytes } from "./format";

describe("fmtBytes", () => {
  it("formats single bytes", () => {
    expect(fmtBytes(0)).toBe("0 B");
    expect(fmtBytes(1)).toBe("1 B");
    expect(fmtBytes(1023)).toBe("1023 B");
  });

  it("switches to KB at 1024", () => {
    expect(fmtBytes(1024)).toBe("1.0 KB");
    expect(fmtBytes(1536)).toBe("1.5 KB");
  });

  it("switches to MB at 1024 * 1024", () => {
    expect(fmtBytes(1024 * 1024)).toBe("1.0 MB");
    expect(fmtBytes(5 * 1024 * 1024)).toBe("5.0 MB");
  });

  it("switches to GB at 1024 * 1024 * 1024", () => {
    expect(fmtBytes(1024 * 1024 * 1024)).toBe("1.00 GB");
    expect(fmtBytes(3.5 * 1024 * 1024 * 1024)).toBe("3.50 GB");
  });
});

describe("el", () => {
  it("creates an element with the given tag", () => {
    const node = el("section");
    expect(node.tagName).toBe("SECTION");
    expect(node.childNodes.length).toBe(0);
  });

  it("attaches text content when provided", () => {
    const node = el("h2", "title");
    expect(node.tagName).toBe("H2");
    expect(node.textContent).toBe("title");
  });

  it("escapes nothing — text is a text node, not HTML", () => {
    const node = el("span", "<script>alert(1)</script>");
    expect(node.childNodes.length).toBe(1);
    expect(node.childNodes[0].nodeType).toBe(3);
    expect(node.textContent).toBe("<script>alert(1)</script>");
  });
});
