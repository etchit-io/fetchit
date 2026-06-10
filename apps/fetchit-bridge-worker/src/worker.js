// fetchit-bridge-worker — Cloudflare Worker for the M4 publish-half (DP2).
//
// Bound to the etchit.io zone on ONLY the routes `/.well-known/webfinger`
// and `/actors*`, it reverse-proxies those (and only those) to the
// fetch>it ActivityPub bridge (`BRIDGE_ORIGIN`). Every other path on
// etchit.io is served directly by GitHub Pages — this Worker is never
// invoked for it, so the static marketing site is untouched.
//
// A remote server resolving `acct:<h>@etchit.io` hits WebFinger here,
// follows the `self` link to `https://etchit.io/actors/<h>` (also proxied
// here), and receives the bridge's canonical, ML-DSA-attested actor doc.

/** Hop-by-hop headers that must not be forwarded across a proxy. */
const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

/**
 * Decide how to handle a request path + method.
 *
 * Returns `"proxy"` for an allowed fediverse route, `"method-not-allowed"`
 * for a fediverse path with a disallowed method, and `null` for any
 * non-fediverse path. The route binding should keep non-fediverse paths
 * away from this Worker entirely; `null` is the fail-safe (return 404,
 * never forward) so the Worker can never act as an open proxy.
 *
 * The `/actors` match is exact-or-subpath (`"/actors"` or `"/actors/…"`)
 * so a lookalike like `/actorsfoo` or `/blog/actors` is NOT proxied.
 *
 * @param {string} pathname
 * @param {string} method
 * @returns {"proxy" | "method-not-allowed" | null}
 */
export function classify(pathname, method) {
  if (pathname === "/.well-known/webfinger") {
    return method === "GET" ? "proxy" : "method-not-allowed";
  }
  if (pathname === "/actors" || pathname.startsWith("/actors/")) {
    // GET serves actor docs + collections; POST registers an actor.
    return method === "GET" || method === "POST" ? "proxy" : "method-not-allowed";
  }
  return null;
}

export default {
  /**
   * @param {Request} request
   * @param {{ BRIDGE_ORIGIN?: string }} env
   */
  async fetch(request, env) {
    const url = new URL(request.url);
    const verdict = classify(url.pathname, request.method);

    if (verdict === null) {
      // Not a fediverse path. The route binding should prevent this; if
      // it ever does not, fail safe rather than become an open proxy.
      return new Response("not found\n", { status: 404 });
    }
    if (verdict === "method-not-allowed") {
      return new Response("method not allowed\n", {
        status: 405,
        headers: { allow: "GET, POST" },
      });
    }

    const origin = (env.BRIDGE_ORIGIN || "").replace(/\/+$/, "");
    if (!origin) {
      return new Response("bridge origin not configured\n", { status: 503 });
    }

    const target = origin + url.pathname + url.search;
    const headers = new Headers();
    for (const [k, v] of request.headers) {
      const lower = k.toLowerCase();
      if (lower !== "host" && !HOP_BY_HOP.has(lower)) {
        headers.set(k, v);
      }
    }

    const init = { method: request.method, headers, redirect: "manual" };
    if (request.method !== "GET" && request.method !== "HEAD") {
      // Buffer the (small) body — actor docs are a few KB, and buffering
      // sidesteps request-stream duplex edge cases.
      init.body = await request.arrayBuffer();
    }

    let upstream;
    try {
      upstream = await fetch(target, init);
    } catch (_e) {
      return new Response("bridge unreachable\n", { status: 502 });
    }

    // Pass the bridge response through unchanged — it already sets the
    // correct `application/jrd+json` / `application/activity+json` types.
    const outHeaders = new Headers();
    for (const [k, v] of upstream.headers) {
      if (!HOP_BY_HOP.has(k.toLowerCase())) {
        outHeaders.set(k, v);
      }
    }
    return new Response(upstream.body, {
      status: upstream.status,
      headers: outHeaders,
    });
  },
};
