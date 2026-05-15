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

  it("rewrites <audio>/<video>/<source> autonomi:// src into data-fetchit-src on the local media-server URL", () => {
    const out = rewriteHtml(
      `<audio src="autonomi://${ADDR}/track.mp3"></audio>` +
        `<video src="autonomi://${ADDR}/v.mp4"></video>` +
        `<video><source src="autonomi://${ADDR}"></video>`,
    );
    const doc = parse(out);
    for (const sel of ["audio", "video[data-fetchit-src]", "source"]) {
      const el = doc.querySelector(sel);
      expect(el?.getAttribute("data-fetchit-src")).toBe(`${MEDIA_BASE}/${ADDR}`);
      expect(el?.hasAttribute("src")).toBe(false);
    }
  });

  it("matches the fetchit:// alias on media srcs too", () => {
    const out = rewriteHtml(`<audio src="fetchit://${ADDR}"></audio>`);
    const audio = parse(out).querySelector("audio");
    expect(audio?.getAttribute("data-fetchit-src")).toBe(`${MEDIA_BASE}/${ADDR}`);
    expect(audio?.hasAttribute("src")).toBe(false);
  });

  it("doesn't touch media src that isn't an Autonomi address", () => {
    const out = rewriteHtml(`<audio src="https://example.com/track.mp3"></audio>`);
    const audio = parse(out).querySelector("audio");
    expect(audio?.getAttribute("src")).toBe("https://example.com/track.mp3");
    expect(audio?.hasAttribute("data-fetchit-src")).toBe(false);
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

describe("rewriteHtml — strips resource hints to prevent preconnect leaks", () => {
  it.each([
    ["preconnect", "https://fonts.gstatic.com"],
    ["dns-prefetch", "https://fonts.googleapis.com"],
    ["prefetch", "https://cdn.example.com/asset.js"],
    ["preload", "https://example.com/main.css"],
    ["modulepreload", "https://example.com/module.js"],
  ])("removes <link rel=%s> pointing at an external host", (rel, href) => {
    const out = rewriteHtml(
      `<html><head><link rel="${rel}" href="${href}"></head><body>x</body></html>`,
    );
    expect(out).not.toContain(href);
    expect(out.toLowerCase()).not.toContain(`rel="${rel}"`);
  });

  it("removes hint links even when the href points at autonomi:// (preconnect is meaningless there)", () => {
    const out = rewriteHtml(
      `<html><head><link rel="preconnect" href="autonomi://${ADDR}"></head><body>x</body></html>`,
    );
    const links = parse(out).head.querySelectorAll('link[rel="preconnect"]');
    expect(links.length).toBe(0);
  });

  it("matches rel case-insensitively and trims whitespace", () => {
    const out = rewriteHtml(
      `<html><head><link rel="  PRECONNECT  " href="https://x.example/"></head><body>x</body></html>`,
    );
    expect(out).not.toContain("https://x.example/");
  });

  it("preserves <link rel=\"stylesheet\"> — CSP handles those at fetch time", () => {
    const out = rewriteHtml(
      `<html><head><link rel="stylesheet" href="autonomi://${ADDR}/style.css"></head><body>x</body></html>`,
    );
    const sheets = parse(out).head.querySelectorAll('link[rel="stylesheet"]');
    expect(sheets.length).toBe(1);
  });
});

describe("rewriteHtml — strips meta-refresh navigations", () => {
  it("removes <meta http-equiv=\"refresh\">", () => {
    const out = rewriteHtml(
      `<html><head><meta http-equiv="refresh" content="0;url=https://attacker"></head><body>x</body></html>`,
    );
    expect(out).not.toContain("https://attacker");
    expect(parse(out).head.querySelectorAll('meta[http-equiv="refresh"]').length).toBe(0);
  });

  it("matches http-equiv case-insensitively", () => {
    const out = rewriteHtml(
      `<html><head><meta HTTP-EQUIV="Refresh" content="0;url=https://attacker"></head><body>x</body></html>`,
    );
    expect(out).not.toContain("https://attacker");
  });
});

describe("rewriteHtml — drops SPA-authored CSP meta tags", () => {
  it("removes Content-Security-Policy meta — only our injected one remains", () => {
    const out = rewriteHtml(
      `<html><head>` +
        `<meta http-equiv="Content-Security-Policy" content="default-src *; report-uri https://attacker">` +
        `</head><body>x</body></html>`,
    );
    const csps = parse(out).head.querySelectorAll('meta[http-equiv="Content-Security-Policy"]');
    // Exactly one — the one we inject.
    expect(csps.length).toBe(1);
    expect(csps[0].getAttribute("content") ?? "").not.toContain("report-uri");
    expect(out).not.toContain("https://attacker");
  });

  it("removes Content-Security-Policy-Report-Only meta as well", () => {
    const out = rewriteHtml(
      `<html><head>` +
        `<meta http-equiv="Content-Security-Policy-Report-Only" content="default-src *; report-uri https://x">` +
        `</head><body>x</body></html>`,
    );
    expect(out).not.toContain("https://x");
    const reportOnly = parse(out).head.querySelectorAll(
      'meta[http-equiv="Content-Security-Policy-Report-Only"]',
    );
    expect(reportOnly.length).toBe(0);
  });
});

describe("rewriteHtml — strips anchor ping", () => {
  it("removes ping attribute from <a> elements", () => {
    const out = rewriteHtml(
      `<html><body><a href="autonomi://${ADDR}" ping="https://tracker https://tracker2">x</a></body></html>`,
    );
    expect(out).not.toContain("https://tracker");
    const a = parse(out).body.querySelector("a");
    expect(a?.hasAttribute("ping")).toBe(false);
    // The href itself is left intact.
    expect(a?.getAttribute("href")).toBe(`autonomi://${ADDR}`);
  });

  it("removes ping attribute from <area> elements", () => {
    const out = rewriteHtml(
      `<html><body><map><area href="autonomi://${ADDR}" ping="https://tracker"></map></body></html>`,
    );
    expect(out).not.toContain("https://tracker");
  });
});

describe("rewriteHtml — injects the media hydration script", () => {
  function hydrationScript(html: string): HTMLScriptElement | null {
    const scripts = parse(html).body.querySelectorAll("script");
    return (Array.from(scripts).find((s) => s.textContent?.includes("data-fetchit-src")) ??
      null) as HTMLScriptElement | null;
  }

  it("appends a hydration script to <body>", () => {
    const out = rewriteHtml(`<html><body><audio src="autonomi://${ADDR}"></audio></body></html>`);
    expect(hydrationScript(out)).toBeTruthy();
  });

  it("the hydration script listens on capture-phase pointerdown and keydown", () => {
    const out = rewriteHtml(`<html><body><audio src="autonomi://${ADDR}"></audio></body></html>`);
    const text = hydrationScript(out)?.textContent ?? "";
    expect(text).toMatch(/addEventListener\('pointerdown',\s*[^,]+,\s*true\)/);
    expect(text).toMatch(/addEventListener\('keydown',\s*[^,]+,\s*true\)/);
  });

  it("the hydration script copies data-fetchit-src to src and calls load()", () => {
    const out = rewriteHtml(`<html><body><audio src="autonomi://${ADDR}"></audio></body></html>`);
    const text = hydrationScript(out)?.textContent ?? "";
    expect(text).toMatch(/getAttribute\('data-fetchit-src'\)/);
    expect(text).toMatch(/setAttribute\('src'/);
    expect(text).toMatch(/\.load\(\)/);
  });

  it("the hydration script also walks <source> children", () => {
    const out = rewriteHtml(`<html><body><audio src="autonomi://${ADDR}"></audio></body></html>`);
    const text = hydrationScript(out)?.textContent ?? "";
    expect(text).toMatch(/querySelectorAll\('source'\)/);
  });

  it("the hydration script is one-shot per element", () => {
    const out = rewriteHtml(`<html><body><audio src="autonomi://${ADDR}"></audio></body></html>`);
    const text = hydrationScript(out)?.textContent ?? "";
    expect(text).toMatch(/_fetchitHydrated/);
  });
});

describe("rewriteHtml — injects the neuter script", () => {
  it("inserts a pre-script that locks RTCPeerConnection and friends", () => {
    const out = rewriteHtml("<html><body>x</body></html>");
    const scripts = Array.from(parse(out).head.querySelectorAll("script"));
    const neuter = scripts.find((s) => s.textContent?.includes("RTCPeerConnection"));
    expect(neuter).toBeTruthy();
    const text = neuter?.textContent ?? "";
    // The four big API-surface categories all show up in the lock list.
    expect(text).toContain("RTCPeerConnection");
    expect(text).toContain("geolocation");
    expect(text).toContain("mediaDevices");
    expect(text).toContain("sendBeacon");
    expect(text).toContain("serviceWorker");
  });

  it("neuter script lands before SPA scripts in the head", () => {
    const out = rewriteHtml(
      `<html><head><script>window.spa = 1;</script></head><body>x</body></html>`,
    );
    const headScripts = Array.from(parse(out).head.querySelectorAll("script"));
    // First script in head must be ours (contains RTCPeerConnection); the
    // SPA's `window.spa = 1` script comes after.
    expect(headScripts[0]?.textContent ?? "").toContain("RTCPeerConnection");
    expect(headScripts[1]?.textContent ?? "").toContain("window.spa");
  });
});
