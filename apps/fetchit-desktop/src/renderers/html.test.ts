import { beforeAll, describe, expect, it } from "vitest";
import { renderHtml } from "./html";
import { setMediaBaseForTesting } from "../mediaUrl";

const ADDR = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

beforeAll(() => setMediaBaseForTesting("http://127.0.0.1:54321"));

function setup(body: string): HTMLIFrameElement {
  const into = document.createElement("div");
  renderHtml({ kind: "html", body }, into, ADDR);
  const iframe = into.querySelector("iframe");
  if (!iframe) throw new Error("no iframe rendered");
  return iframe;
}

describe("renderHtml", () => {
  it("mounts an iframe inside a .rendered-html wrapper", () => {
    const into = document.createElement("div");
    renderHtml({ kind: "html", body: "<p>hi</p>" }, into, ADDR);
    expect(into.querySelector(".rendered-html > iframe")).toBeTruthy();
  });

  it("enables only allow-scripts, allow-forms, and allow-fullscreen in sandbox", () => {
    const sandbox = setup("<p>x</p>").getAttribute("sandbox") ?? "";
    expect(sandbox).toContain("allow-scripts");
    expect(sandbox).toContain("allow-forms");
    expect(sandbox).toContain("allow-fullscreen");
    expect(sandbox).not.toContain("allow-same-origin");
    expect(sandbox).not.toContain("allow-top-navigation");
    expect(sandbox).not.toContain("allow-popups");
    expect(sandbox).not.toContain("allow-pointer-lock");
  });

  it("sets referrerpolicy=no-referrer", () => {
    expect(setup("").getAttribute("referrerpolicy")).toBe("no-referrer");
  });

  it("sets allowfullscreen so <video> can enter fullscreen", () => {
    expect(setup("").hasAttribute("allowfullscreen")).toBe(true);
  });

  it("populates srcdoc with the rewritten HTML", () => {
    const srcdoc = setup("<p>x</p>").getAttribute("srcdoc") ?? "";
    expect(srcdoc.toLowerCase()).toMatch(/^<!doctype html>/);
    expect(srcdoc).toContain("Content-Security-Policy");
    expect(srcdoc).toContain(`autonomi://${ADDR}/`);
  });
});
