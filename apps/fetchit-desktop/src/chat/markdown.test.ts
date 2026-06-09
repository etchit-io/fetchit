import { describe, expect, it } from "vitest";
import { appendInlineMarkdown } from "./markdown";

function render(text: string): HTMLElement {
  const host = document.createElement("div");
  appendInlineMarkdown(host, text);
  return host;
}

describe("appendInlineMarkdown", () => {
  it("emits plain text as a single text node", () => {
    const host = render("just words");
    expect(host.childNodes.length).toBe(1);
    expect(host.childNodes[0].nodeType).toBe(Node.TEXT_NODE);
    expect(host.textContent).toBe("just words");
  });

  it("renders the safe inline subset to semantic elements", () => {
    expect(render("a **b** c").querySelector("strong")?.textContent).toBe("b");
    expect(render("a *b* c").querySelector("em")?.textContent).toBe("b");
    expect(render("a _b_ c").querySelector("em")?.textContent).toBe("b");
    expect(render("a `b` c").querySelector("code")?.textContent).toBe("b");
    expect(render("a ~~b~~ c").querySelector("del")?.textContent).toBe("b");
  });

  it("keeps surrounding text around a span", () => {
    const host = render("a **b** c");
    expect(host.childNodes.length).toBe(3);
    expect(host.childNodes[0].textContent).toBe("a ");
    expect((host.childNodes[1] as HTMLElement).tagName).toBe("STRONG");
    expect(host.childNodes[2].textContent).toBe(" c");
  });

  it("treats code-span content as literal, never nested markup", () => {
    const host = render("`**x**`");
    expect(host.querySelector("strong")).toBeNull();
    expect(host.querySelector("code")?.textContent).toBe("**x**");
  });

  it("never interprets HTML in the input as markup", () => {
    const evil = "<img src=x onerror=alert(1)><script>alert(2)</script>";
    const host = render(evil);
    expect(host.querySelector("img")).toBeNull();
    expect(host.querySelector("script")).toBeNull();
    expect(host.textContent).toBe(evil);
  });

  it("leaves unmatched delimiters as literal text", () => {
    expect(render("**not closed").querySelector("strong")).toBeNull();
    expect(render("**not closed").textContent).toBe("**not closed");
    expect(render("a * b").querySelector("em")).toBeNull();
    expect(render("a * b").textContent).toBe("a * b");
  });

  it("does not span emphasis across a newline", () => {
    const host = render("a *b\nc* d");
    expect(host.querySelector("em")).toBeNull();
    expect(host.textContent).toBe("a *b\nc* d");
  });
});
