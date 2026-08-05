// fetchit-bridge-worker -- Cloudflare Worker for the M4 publish-half (DP2).
//
// Bound to the etchit.io zone on ONLY the fediverse routes
// (`/.well-known/webfinger`, `/actors*`, and the `/v1/actors*` registry
// write surface), it reverse-proxies those (and only those) to the
// fetch>it ActivityPub bridge (`BRIDGE_ORIGIN`). Every other path on
// etchit.io is served directly by GitHub Pages -- this Worker is never
// invoked for it, so the static marketing site is untouched.
//
// A remote server resolving `acct:<h>@etchit.io` hits WebFinger here,
// follows the `self` link to `https://etchit.io/actors/<h>` (also proxied
// here), and receives the bridge's canonical, ML-DSA-attested actor doc.
// A fetch>it client self-registers its handle with POST `/v1/actors` and
// rotates its relay hint with PUT `/v1/actors/<h>`.

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
 * The methods this Worker proxies for `pathname`, or `null` if the path
 * is not a frontable fediverse route. Single source of truth for both the
 * proxy decision and the 405 `Allow` header, so the two can never drift.
 *
 * Read surface (GET): `/.well-known/webfinger`, `/actors`, and
 * `/actors/...` (actor docs + their followers/outbox collections). Write
 * surface: POST `/v1/actors` registers a handle, PUT `/v1/actors/<h>`
 * rotates its relay hint. The `/actors` and `/v1/actors` prefixes are
 * disjoint, and each match is exact-or-subpath so a lookalike like
 * `/actorsfoo` or `/v1/actorsfoo` is NOT proxied. Registration is no
 * longer accepted on `/actors` (it moved to `/v1/actors`), so the read
 * surface is GET-only.
 *
 * Two `/actors/<h>/...` paths carry their own methods: `/inbox` accepts
 * inbound POST deliveries from remote servers, and `/avatar` is the
 * profile picture -- public GET (it is the `icon` URL every fediverse
 * server fetches) plus owner-authenticated POST/DELETE, which the bridge
 * itself gates with `bridge-auth-v1`.
 *
 * @param {string} pathname
 * @returns {string[] | null}
 */
function routeMethods(pathname) {
  if (pathname === "/.well-known/webfinger") return ["GET"];
  if (pathname === "/v1/actors") return ["POST"];
  if (pathname.startsWith("/v1/actors/")) return ["PUT"];
  // An actor's inbox accepts inbound POST deliveries from remote
  // fediverse servers; every other /actors/* path is GET-only.
  if (pathname.endsWith("/inbox")) return ["POST"];
  if (pathname.startsWith("/actors/") && pathname.endsWith("/avatar")) {
    return ["GET", "POST", "DELETE"];
  }
  if (pathname === "/actors" || pathname.startsWith("/actors/")) return ["GET"];
  return null;
}

/**
 * Decide how to handle a request path + method.
 *
 * Returns `"proxy"` for an allowed fediverse route, `"method-not-allowed"`
 * for a fediverse path with a disallowed method, and `null` for any
 * non-fediverse path. The route binding should keep non-fediverse paths
 * away from this Worker entirely; `null` is the fail-safe (return 404,
 * never forward) so the Worker can never act as an open proxy.
 *
 * @param {string} pathname
 * @param {string} method
 * @returns {"proxy" | "method-not-allowed" | null}
 */
export function classify(pathname, method) {
  const methods = routeMethods(pathname);
  if (methods === null) {
    return null;
  }
  return methods.includes(method) ? "proxy" : "method-not-allowed";
}

/**
 * The `Allow` header value for a 405 on a fediverse path: the methods
 * `routeMethods` permits for it, comma-joined. Empty string for a
 * non-fediverse path (the handler never 405s those).
 *
 * @param {string} pathname
 * @returns {string}
 */
export function allowedMethods(pathname) {
  const methods = routeMethods(pathname);
  return methods === null ? "" : methods.join(", ");
}

/**
 * Build the headers for the upstream request: drop `host` + hop-by-hop
 * headers, then SET the origin's rate-limit source header (`x-real-ip`)
 * from Cloudflare's authoritative `cfConnectingIp`. SET (not append)
 * overwrites any client-supplied `x-real-ip`, and an absent
 * `cfConnectingIp` deletes it, so a forged value can never reach the
 * origin (Alice F2). The origin keys its registry rate limiter on this
 * header and is reachable only via this Worker.
 *
 * @param {Headers} requestHeaders
 * @param {string | null} cfConnectingIp
 * @returns {Headers}
 */
export function buildForwardHeaders(requestHeaders, cfConnectingIp) {
  const headers = new Headers();
  for (const [k, v] of requestHeaders) {
    const lower = k.toLowerCase();
    if (lower !== "host" && !HOP_BY_HOP.has(lower)) {
      headers.set(k, v);
    }
  }
  if (cfConnectingIp) {
    headers.set("x-real-ip", cfConnectingIp);
  } else {
    headers.delete("x-real-ip");
  }
  return headers;
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
        headers: { allow: allowedMethods(url.pathname) },
      });
    }

    const origin = (env.BRIDGE_ORIGIN || "").replace(/\/+$/, "");
    if (!origin) {
      return new Response("bridge origin not configured\n", { status: 503 });
    }

    const target = origin + url.pathname + url.search;
    const headers = buildForwardHeaders(
      request.headers,
      request.headers.get("CF-Connecting-IP"),
    );

    const init = { method: request.method, headers, redirect: "manual" };
    if (request.method !== "GET" && request.method !== "HEAD") {
      // Buffer the (small) body -- actor docs are a few KB, and buffering
      // sidesteps request-stream duplex edge cases.
      init.body = await request.arrayBuffer();
    }

    let upstream;
    try {
      upstream = await fetch(target, init);
    } catch (_e) {
      return new Response("bridge unreachable\n", { status: 502 });
    }

    // Pass the bridge response through unchanged -- it already sets the
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
