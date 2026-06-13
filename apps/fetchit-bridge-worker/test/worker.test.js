import { describe, it, expect } from "vitest";
import { classify, buildForwardHeaders } from "../src/worker.js";

describe("classify — the routing + security decision", () => {
  it("proxies a GET WebFinger request", () => {
    expect(classify("/.well-known/webfinger", "GET")).toBe("proxy");
  });

  it("rejects a non-GET WebFinger method", () => {
    expect(classify("/.well-known/webfinger", "POST")).toBe("method-not-allowed");
  });

  it("proxies GET + POST on the actors collection", () => {
    expect(classify("/actors", "GET")).toBe("proxy");
    expect(classify("/actors", "POST")).toBe("proxy");
  });

  it("proxies GET on an actor doc + its collections", () => {
    expect(classify("/actors/josh", "GET")).toBe("proxy");
    expect(classify("/actors/josh/followers", "GET")).toBe("proxy");
    expect(classify("/actors/josh/outbox", "GET")).toBe("proxy");
  });

  it("rejects unsupported methods on /actors", () => {
    expect(classify("/actors/josh", "DELETE")).toBe("method-not-allowed");
    expect(classify("/actors/josh", "PUT")).toBe("method-not-allowed");
  });

  it("does NOT proxy the marketing site or ops endpoints", () => {
    expect(classify("/", "GET")).toBeNull();
    expect(classify("/index.html", "GET")).toBeNull();
    expect(classify("/etch/", "GET")).toBeNull();
    expect(classify("/city", "GET")).toBeNull();
    expect(classify("/health", "GET")).toBeNull(); // bridge ops — not frontable
    expect(classify("/metrics", "GET")).toBeNull();
  });

  it("does NOT proxy a path that merely starts with the prefix string", () => {
    // exact-or-subpath match: /actorsfoo and /blog/actors are not actors
    expect(classify("/actorsfoo", "GET")).toBeNull();
    expect(classify("/blog/actors-explained", "GET")).toBeNull();
    expect(classify("/.well-known/webfinger-evil", "GET")).toBeNull();
  });
});

describe("buildForwardHeaders — the rate-limit source-IP lock (F2)", () => {
  it("sets x-real-ip from CF-Connecting-IP, overwriting a client-supplied value", () => {
    const inbound = new Headers({
      "x-real-ip": "1.2.3.4",
      "content-type": "application/json",
    });
    const out = buildForwardHeaders(inbound, "203.0.113.9");
    expect(out.get("x-real-ip")).toBe("203.0.113.9");
    expect(out.get("content-type")).toBe("application/json");
  });

  it("strips a client-supplied x-real-ip when CF-Connecting-IP is absent", () => {
    const inbound = new Headers({ "x-real-ip": "1.2.3.4" });
    const out = buildForwardHeaders(inbound, null);
    expect(out.get("x-real-ip")).toBeNull();
  });

  it("drops host + hop-by-hop headers but keeps the rest", () => {
    const inbound = new Headers({
      host: "etchit.io",
      connection: "keep-alive",
      "content-type": "application/activity+json",
    });
    const out = buildForwardHeaders(inbound, "203.0.113.9");
    expect(out.get("host")).toBeNull();
    expect(out.get("connection")).toBeNull();
    expect(out.get("content-type")).toBe("application/activity+json");
  });
});
