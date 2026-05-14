// Spot tests per language — exhaustive coverage isn't the goal; these confirm
// the regex passes wire up correctly and the priority ordering matches the
// Android reference.

import { describe, expect, it } from "vitest";
import type { Token, TokenColor } from "./tokens";
import { rust } from "./rust";
import { jsts } from "./jsts";
import { python } from "./python";
import { json } from "./json";
import { html } from "./html";
import { css } from "./css";
import { bash } from "./bash";
import { yaml } from "./yaml";
import { sql } from "./sql";

function colorOf(_text: string, tokens: Token[], index: number): TokenColor | null {
  let winner: TokenColor | null = null;
  for (const t of tokens) {
    if (index >= t.start && index < t.end) winner = t.color;
  }
  return winner;
}

describe("rust", () => {
  it("colors keywords, strings, comments, numbers", () => {
    const src = `fn main() { let x: i32 = 42; let s = "hi"; /* note */ }`;
    const t = rust(src);
    expect(colorOf(src, t, src.indexOf("fn"))).toBe("keyword");
    expect(colorOf(src, t, src.indexOf("let"))).toBe("keyword");
    expect(colorOf(src, t, src.indexOf("42"))).toBe("number");
    expect(colorOf(src, t, src.indexOf("\"hi\""))).toBe("string");
    expect(colorOf(src, t, src.indexOf("/* note */"))).toBe("comment");
  });

  it("colors attributes as literal", () => {
    const src = `#[derive(Debug)]`;
    const t = rust(src);
    expect(colorOf(src, t, 0)).toBe("literal");
  });
});

describe("jsts", () => {
  it("colors keywords and builtins", () => {
    const src = `import { foo } from "./bar"; console.log(true);`;
    const t = jsts(src);
    expect(colorOf(src, t, src.indexOf("import"))).toBe("keyword");
    expect(colorOf(src, t, src.indexOf("from"))).toBe("keyword");
    expect(colorOf(src, t, src.indexOf("console"))).toBe("literal");
    expect(colorOf(src, t, src.indexOf("true"))).toBe("literal");
  });

  it("handles template literals", () => {
    const src = "const s = `hi ${name}`;";
    const t = jsts(src);
    expect(colorOf(src, t, src.indexOf("`"))).toBe("string");
  });
});

describe("python", () => {
  it("colors def/class as keyword, None/True/False as literal", () => {
    const src = "def foo():\n    return None";
    const t = python(src);
    expect(colorOf(src, t, src.indexOf("def"))).toBe("keyword");
    expect(colorOf(src, t, src.indexOf("return"))).toBe("keyword");
    expect(colorOf(src, t, src.indexOf("None"))).toBe("literal");
  });

  it("recognises triple-quoted strings", () => {
    const src = `def f():\n    """doc"""\n    return 1`;
    const t = python(src);
    expect(colorOf(src, t, src.indexOf('"""doc"""'))).toBe("string");
  });

  it("recognises decorators", () => {
    const src = "@dataclass\nclass X: pass";
    const t = python(src);
    expect(colorOf(src, t, 0)).toBe("literal");
  });
});

describe("json", () => {
  it("colors keys as keyword and values per type", () => {
    const src = `{"name": "x", "age": 30, "ok": true}`;
    const t = json(src);
    const keyStart = src.indexOf('"name"');
    expect(colorOf(src, t, keyStart)).toBe("keyword");
    expect(colorOf(src, t, src.indexOf('"x"'))).toBe("string");
    expect(colorOf(src, t, src.indexOf("30"))).toBe("number");
    expect(colorOf(src, t, src.indexOf("true"))).toBe("literal");
  });
});

describe("html", () => {
  it("colors tags, attrs, strings, and embedded JS", () => {
    const src = `<div class="x"><script>const y = 1;</script></div>`;
    const t = html(src);
    expect(colorOf(src, t, src.indexOf("<div"))).toBe("keyword");
    expect(colorOf(src, t, src.indexOf("class"))).toBe("literal");
    expect(colorOf(src, t, src.indexOf('"x"'))).toBe("string");
    // Inner const should pick up jsts keyword colour, not html attr literal.
    expect(colorOf(src, t, src.indexOf("const"))).toBe("keyword");
    expect(colorOf(src, t, src.indexOf("1"))).toBe("number");
  });

  it("colors HTML comments", () => {
    const src = `<!-- hi --><p>x</p>`;
    const t = html(src);
    expect(colorOf(src, t, 0)).toBe("comment");
  });
});

describe("css", () => {
  it("colors properties, numbers with units, hex colors, at-rules", () => {
    const src = `@media (min-width: 800px) { .a { color: #abc; margin: 10px; } }`;
    const t = css(src);
    expect(colorOf(src, t, 0)).toBe("keyword");                          // @media
    expect(colorOf(src, t, src.indexOf("color"))).toBe("literal");      // property
    expect(colorOf(src, t, src.indexOf("#abc"))).toBe("literal");       // hex
    expect(colorOf(src, t, src.indexOf("10px"))).toBe("number");        // number+unit
  });
});

describe("bash", () => {
  it("colors keywords, vars, strings, numbers, comments", () => {
    const src = `for f in $HOME; do echo "$f"; done # loop`;
    const t = bash(src);
    expect(colorOf(src, t, 0)).toBe("keyword");                   // for
    expect(colorOf(src, t, src.indexOf("$HOME"))).toBe("literal");
    expect(colorOf(src, t, src.indexOf("# loop"))).toBe("comment");
  });
});

describe("yaml", () => {
  it("colors keys, list markers, literals", () => {
    const src = `name: fetchit\nfeatures:\n  - tabs\n  - cache\nenabled: true`;
    const t = yaml(src);
    expect(colorOf(src, t, 0)).toBe("keyword");                              // key "name"
    expect(colorOf(src, t, src.indexOf("- tabs") - 0)).toBe("literal");      // "-"
    expect(colorOf(src, t, src.indexOf("true"))).toBe("literal");
  });
});

describe("sql", () => {
  it("colors keywords case-insensitively and strings", () => {
    const src = `select * from users where name = 'alice';`;
    const t = sql(src);
    expect(colorOf(src, t, 0)).toBe("keyword");
    expect(colorOf(src, t, src.indexOf("from"))).toBe("keyword");
    expect(colorOf(src, t, src.indexOf("'alice'"))).toBe("string");
  });
});
