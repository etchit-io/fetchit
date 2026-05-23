/**
 * Static check: does an HTML document reference any external (non-Autonomi,
 * non-inline, non-local) subresources? Used by `renderHtml` to flag pages
 * that are *verifiably* self-contained — content safe by its own nature,
 * not just by the sandbox's egress block.
 *
 * Scope: image / script / stylesheet / media / iframe / embed / object
 * loads (which fire on render), plus CSS `url(https?://…)` inside
 * `<style>` blocks and inline `style="…"` attributes. Anchor `<a href>`
 * and `<form action>` are *not* counted — they are click-time targets,
 * not load-time subresources, and the reader refuses non-Autonomi
 * top-level navigation regardless.
 *
 * A runtime `fetch("https://…")` in author JS can't be statically seen
 * here; the strict CSP `connect-src` blocks it at load time anyway.
 * "Self-contained" means the *markup* references nothing external; the
 * sandbox catches anything the script attempts.
 */
export function isSelfContained(body: string): boolean {
  const doc = new DOMParser().parseFromString(body, "text/html");
  const EXTERNAL = /^https?:\/\//i;

  const ATTRS: Array<readonly [string, string]> = [
    ["img[src]", "src"],
    ["script[src]", "src"],
    ["link[href]", "href"],
    ["audio[src]", "src"],
    ["video[src]", "src"],
    ["source[src]", "src"],
    ["iframe[src]", "src"],
    ["embed[src]", "src"],
    ["object[data]", "data"],
  ];
  for (const [sel, attr] of ATTRS) {
    for (const el of doc.querySelectorAll(sel)) {
      if (EXTERNAL.test(el.getAttribute(attr) ?? "")) return false;
    }
  }

  // srcset is a comma-separated list of "<URL> <descriptor>" entries.
  for (const el of doc.querySelectorAll("img[srcset], source[srcset]")) {
    const srcset = el.getAttribute("srcset") ?? "";
    for (const entry of srcset.split(",")) {
      const url = entry.trim().split(/\s+/)[0] ?? "";
      if (EXTERNAL.test(url)) return false;
    }
  }

  // CSS — `url(https?://…)` in <style> blocks and in inline `style="…"`.
  const CSS_URL = /url\s*\(\s*['"]?\s*https?:\/\//i;
  for (const style of doc.querySelectorAll("style")) {
    if (CSS_URL.test(style.textContent ?? "")) return false;
  }
  for (const el of doc.querySelectorAll("[style]")) {
    if (CSS_URL.test(el.getAttribute("style") ?? "")) return false;
  }

  return true;
}
