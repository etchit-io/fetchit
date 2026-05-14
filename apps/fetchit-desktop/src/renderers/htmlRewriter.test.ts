import { describe, expect, it } from "vitest";
import { rewriteHtml as rewrite } from "./htmlRewriter";

const ADDR = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const MEDIA_BASE = "http://127.0.0.1:54321";

function rewriteHtml(body: string, address: string = ADDR): string {
  return rewrite(body, address, MEDIA_BASE);
}

function parse(html: string): Document {
  return new DOMParser().parseFromString(html, "text/html");
}

describe("rewriteHtml — preserves authored URLs", () => {
  it("leaves non-media autonomi:// references untouched (both schemes are registered with Tauri)", () => {
    const out = rewriteHtml(
      `<a href="autonomi://${ADDR}">a</a>` +
        `<img src="autonomi://${ADDR}/img.png">` +
        `<script src="autonomi://${ADDR}/main.js"></script>` +
        `<link rel="stylesheet" href="autonomi://${ADDR}/style.css">` +
        `<form action="autonomi://${ADDR}/submit"></form>`,
    );
    const doc = parse(out);
    expect(doc.querySelector("a")?.getAttribute("href")).toBe(`autonomi://${ADDR}`);
    expect(doc.querySelector("img")?.getAttribute("src")).toBe(`autonomi://${ADDR}/img.png`);
    expect(doc.querySelector("script[src]")?.getAttribute("src")).toBe(
      `autonomi://${ADDR}/main.js`,
    );
    expect(doc.querySelector("link")?.getAttribute("href")).toBe(`autonomi://${ADDR}/style.css`);
    expect(doc.querySelector("form")?.getAttribute("action")).toBe(`autonomi://${ADDR}/submit`);
  });

  it("rewrites <audio>/<video>/<source> autonomi:// src to the local media-server URL", () => {
    const out = rewriteHtml(
      `<audio src="autonomi://${ADDR}/track.mp3"></audio>` +
        `<video src="autonomi://${ADDR}/v.mp4"></video>` +
        `<video><source src="autonomi://${ADDR}"></video>`,
    );
    const doc = parse(out);
    expect(doc.querySelector("audio")?.getAttribute("src")).toBe(`${MEDIA_BASE}/${ADDR}`);
    expect(doc.querySelector("video[src]")?.getAttribute("src")).toBe(`${MEDIA_BASE}/${ADDR}`);
    expect(doc.querySelector("source")?.getAttribute("src")).toBe(`${MEDIA_BASE}/${ADDR}`);
  });

  it("matches the fetchit:// alias on media srcs too", () => {
    const out = rewriteHtml(`<audio src="fetchit://${ADDR}"></audio>`);
    expect(parse(out).querySelector("audio")?.getAttribute("src")).toBe(`${MEDIA_BASE}/${ADDR}`);
  });

  it("doesn't touch media src that isn't an Autonomi address", () => {
    const out = rewriteHtml(`<audio src="https://example.com/track.mp3"></audio>`);
    expect(parse(out).querySelector("audio")?.getAttribute("src")).toBe(
      "https://example.com/track.mp3",
    );
  });

  it("leaves non-autonomi schemes untouched too", () => {
    const html = `
      <a href="https://example.com">a</a>
      <a href="mailto:a@b.c">b</a>
      <a href="javascript:alert(1)">c</a>
      <a href="#anchor">d</a>
      <a href="/relative">e</a>
    `;
    const doc = parse(rewriteHtml(html, ADDR));
    const links = doc.querySelectorAll("a");
    expect(links[0].getAttribute("href")).toBe("https://example.com");
    expect(links[1].getAttribute("href")).toBe("mailto:a@b.c");
    expect(links[2].getAttribute("href")).toBe("javascript:alert(1)");
    expect(links[3].getAttribute("href")).toBe("#anchor");
    expect(links[4].getAttribute("href")).toBe("/relative");
  });
});

describe("rewriteHtml — security boundaries", () => {
  it("injects a CSP meta in <head>", () => {
    const out = rewriteHtml(`<html><body></body></html>`, ADDR);
    const csp = parse(out).querySelector("meta[http-equiv='Content-Security-Policy']");
    expect(csp).toBeTruthy();
    const content = csp!.getAttribute("content") ?? "";
    expect(content).toMatch(/default-src 'self' fetchit: autonomi:/);
    expect(content).toMatch(/connect-src 'self' fetchit: autonomi:/);
    expect(content).toMatch(/frame-src 'none'/);
    expect(content).toMatch(/object-src 'none'/);
  });

  it("the injected CSP allows both fetchit: and autonomi: schemes everywhere they could appear", () => {
    const out = rewriteHtml(`<html></html>`, ADDR);
    const content =
      parse(out)
        .querySelector("meta[http-equiv='Content-Security-Policy']")
        ?.getAttribute("content") ?? "";
    for (const directive of [
      "default-src",
      "script-src",
      "style-src",
      "img-src",
      "media-src",
      "font-src",
      "connect-src",
      "base-uri",
      "form-action",
    ]) {
      expect(content).toContain(`${directive} 'self' fetchit: autonomi:`);
    }
  });

  it("the injected CSP allows no remote http(s) origins (only the localhost media server)", () => {
    const out = rewriteHtml(`<html></html>`, ADDR);
    const content =
      parse(out)
        .querySelector("meta[http-equiv='Content-Security-Policy']")
        ?.getAttribute("content") ?? "";
    // http(s) URLs are only allowed if pointing at 127.0.0.1 (our media server).
    expect(content).not.toMatch(/\bhttps?:\/\/(?!127\.0\.0\.1)/);
    expect(content).not.toMatch(/\*\s/);
  });

  it("the CSP names the configured media base for media-src and connect-src", () => {
    const out = rewriteHtml(`<html></html>`);
    const content =
      parse(out)
        .querySelector("meta[http-equiv='Content-Security-Policy']")
        ?.getAttribute("content") ?? "";
    expect(content).toContain(`media-src 'self' fetchit: autonomi: data: blob: ${MEDIA_BASE}`);
    expect(content).toContain(`connect-src 'self' fetchit: autonomi: ${MEDIA_BASE}`);
  });

  it("sets <base href> to autonomi://<addr>/", () => {
    const out = rewriteHtml(`<html></html>`, ADDR);
    expect(parse(out).querySelector("base")?.getAttribute("href")).toBe(`autonomi://${ADDR}/`);
  });

  it("replaces any base the document tried to set", () => {
    const malicious = `<html><head><base href="https://attacker.example/"></head></html>`;
    const out = rewriteHtml(malicious, ADDR);
    const bases = parse(out).querySelectorAll("base");
    expect(bases.length).toBe(1);
    expect(bases[0].getAttribute("href")).toBe(`autonomi://${ADDR}/`);
  });

  it("emits a doctype", () => {
    const out = rewriteHtml(`<html><body></body></html>`, ADDR);
    expect(out.toLowerCase()).toMatch(/^<!doctype html>/);
  });
});

describe("rewriteHtml — link interceptor", () => {
  function interceptor(html: string): HTMLScriptElement | null {
    const scripts = parse(html).body.querySelectorAll("script");
    return (Array.from(scripts).find((s) => s.textContent?.includes("fetchit:open")) ??
      null) as HTMLScriptElement | null;
  }

  it("appends an interceptor script to <body>", () => {
    const out = rewriteHtml(`<html><body></body></html>`, ADDR);
    expect(interceptor(out)).toBeTruthy();
  });

  it("the script postMessages the parent with the address", () => {
    const out = rewriteHtml(`<html><body></body></html>`, ADDR);
    const text = interceptor(out)?.textContent ?? "";
    expect(text).toMatch(/parent\.postMessage/);
    expect(text).toMatch(/fetchit:open/);
    expect(text).toMatch(/preventDefault/);
  });

  it("the script reports target=current by default and target=new on modifier keys", () => {
    const out = rewriteHtml(`<html><body></body></html>`, ADDR);
    const text = interceptor(out)?.textContent ?? "";
    expect(text).toMatch(/ctrlKey/);
    expect(text).toMatch(/metaKey/);
    expect(text).toMatch(/shiftKey/);
    expect(text).toMatch(/button === 1/);
    expect(text).toMatch(/target:\s*newTab\s*\?\s*'new'\s*:\s*'current'/);
  });

  it("the script handles both click and auxclick (middle-button)", () => {
    const out = rewriteHtml(`<html><body></body></html>`, ADDR);
    const text = interceptor(out)?.textContent ?? "";
    expect(text).toMatch(/addEventListener\('click'/);
    expect(text).toMatch(/addEventListener\('auxclick'/);
  });

  it("the script targets autonomi:// and fetchit:// only", () => {
    const out = rewriteHtml(`<html><body></body></html>`, ADDR);
    const text = interceptor(out)?.textContent ?? "";
    expect(text).toMatch(/fetchit\|autonomi/);
    expect(text).toMatch(/\[0-9a-fA-F\]\{64\}/);
  });

  it("the script catches fetchit://back and posts kind:'fetchit:back'", () => {
    const out = rewriteHtml(`<html><body></body></html>`, ADDR);
    const text = interceptor(out)?.textContent ?? "";
    expect(text).toMatch(/fetchit:back/);
    expect(text).toMatch(/\(\?:fetchit\|autonomi\):.*back/);
  });

  it("appends only one interceptor regardless of body markup", () => {
    const out = rewriteHtml(
      `<html><body><a href="autonomi://${ADDR}">a</a><a href="autonomi://${ADDR}">b</a></body></html>`,
      ADDR,
    );
    const scripts = parse(out).body.querySelectorAll("script");
    const interceptors = Array.from(scripts).filter((s) =>
      s.textContent?.includes("fetchit:open"),
    );
    expect(interceptors.length).toBe(1);
  });
});
