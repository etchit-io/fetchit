import { describe, expect, it } from "vitest";
import { applyTokensInto, colorRule, embedSubLanguage, type Token, type Tokenizer } from "./tokens";

describe("colorRule", () => {
  it("emits one token per match", () => {
    const out: Token[] = [];
    colorRule(out, "fn a() {} fn b() {}", /fn/, "keyword");
    expect(out).toEqual([
      { start: 0, end: 2, color: "keyword" },
      { start: 10, end: 12, color: "keyword" },
    ]);
  });

  it("works whether or not the source regex already has g", () => {
    const a: Token[] = [];
    const b: Token[] = [];
    colorRule(a, "1 2 3", /\d/, "number");
    colorRule(b, "1 2 3", /\d/g, "number");
    expect(a).toEqual(b);
  });

  it("does not loop on zero-width matches", () => {
    const out: Token[] = [];
    colorRule(out, "abc", /(?=a)/, "keyword");
    // The zero-width match would loop forever without the safety bump;
    // we just need to confirm we returned.
    expect(out.length).toBe(0);
  });
});

describe("applyTokensInto", () => {
  it("emits a plain text node when no tokens", () => {
    const host = document.createElement("pre");
    applyTokensInto(host, "hello", []);
    expect(host.childNodes.length).toBe(1);
    expect(host.firstChild?.nodeType).toBe(Node.TEXT_NODE);
    expect(host.textContent).toBe("hello");
  });

  it("wraps colored runs in span.tok-<color> and leaves uncolored as text", () => {
    const host = document.createElement("pre");
    applyTokensInto(host, "fn main", [{ start: 0, end: 2, color: "keyword" }]);
    expect(host.children.length).toBe(1);
    const span = host.children[0] as HTMLElement;
    expect(span.tagName).toBe("SPAN");
    expect(span.className).toBe("tok-keyword");
    expect(span.textContent).toBe("fn");
    // " main" is a separate text node.
    expect(host.lastChild?.nodeType).toBe(Node.TEXT_NODE);
    expect(host.lastChild?.textContent).toBe(" main");
  });

  it("later tokens win over earlier (overlap resolution)", () => {
    const host = document.createElement("pre");
    // "fn" first colored as keyword, then the whole text colored as string;
    // every char should end up colored string.
    applyTokensInto(host, "fn main", [
      { start: 0, end: 2, color: "keyword" },
      { start: 0, end: 7, color: "string" },
    ]);
    expect(host.children.length).toBe(1);
    const span = host.children[0] as HTMLElement;
    expect(span.className).toBe("tok-string");
    expect(span.textContent).toBe("fn main");
  });

  it("escapes HTML in source via textContent, never innerHTML", () => {
    const host = document.createElement("pre");
    applyTokensInto(host, "<script>alert(1)</script>", [
      { start: 0, end: 8, color: "keyword" },
    ]);
    // The injected HTML must not have become a real element.
    expect(host.querySelectorAll("script").length).toBe(0);
    expect(host.textContent).toBe("<script>alert(1)</script>");
  });
});

describe("embedSubLanguage", () => {
  it("merges sub-language tokens at the body offset and drops outer tokens fully inside", () => {
    const inner: Tokenizer = (s) => {
      // simple inner: color every "x" as keyword.
      const out: Token[] = [];
      for (let i = 0; i < s.length; i++) if (s[i] === "x") out.push({ start: i, end: i + 1, color: "keyword" });
      return out;
    };
    const outerStart = "<style>";
    const body = "abxcdx";
    const text = `${outerStart}${body}</style>`;
    // Pre-populate `out` with an outer-pass token entirely inside the body —
    // it should be dropped by embedSubLanguage so the inner tokens can claim
    // the range.
    const out: Token[] = [
      { start: outerStart.length, end: outerStart.length + body.length, color: "string" },
    ];
    embedSubLanguage(out, text, /<style[^>]*>([\s\S]*?)<\/style>/i, inner);
    // The outer string token must be gone, and the inner keyword tokens must
    // be at the absolute offsets.
    const colors = out.map((t) => t.color);
    expect(colors).not.toContain("string");
    const keywordStarts = out.filter((t) => t.color === "keyword").map((t) => t.start);
    expect(keywordStarts).toEqual([outerStart.length + 2, outerStart.length + 5]);
  });
});
