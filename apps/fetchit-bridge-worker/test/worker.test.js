import { describe, it, expect } from "vitest";
import { classify, allowedMethods, buildForwardHeaders } from "../src/worker.js";

describe("classify -- the routing + security decision", () => {
  it("proxies a GET WebFinger request", () => {
    expect(classify("/.well-known/webfinger", "GET")).toBe("proxy");
  });

  it("rejects a non-GET WebFinger method", () => {
    expect(classify("/.well-known/webfinger", "POST")).toBe("method-not-allowed");
  });

  it("proxies GET on the actors collection but no longer POST (registration moved to /v1/actors)", () => {
    expect(classify("/actors", "GET")).toBe("proxy");
    expect(classify("/actors", "POST")).toBe("method-not-allowed");
  });

  it("proxies GET on an actor doc + its collections", () => {
    expect(classify("/actors/josh", "GET")).toBe("proxy");
    expect(classify("/actors/josh/followers", "GET")).toBe("proxy");
    expect(classify("/actors/josh/outbox", "GET")).toBe("proxy");
  });

  it("proxies inbound POST to an actor inbox, rejects other methods", () => {
    expect(classify("/actors/josh/inbox", "POST")).toBe("proxy");
    expect(classify("/actors/josh/inbox", "GET")).toBe("method-not-allowed");
  });

  it("rejects unsupported methods on /actors", () => {
    expect(classify("/actors/josh", "DELETE")).toBe("method-not-allowed");
    expect(classify("/actors/josh", "PUT")).toBe("method-not-allowed");
  });

  it("proxies POST on the /v1/actors registry collection", () => {
    expect(classify("/v1/actors", "POST")).toBe("proxy");
  });

  it("rejects non-POST on /v1/actors", () => {
    expect(classify("/v1/actors", "GET")).toBe("method-not-allowed");
    expect(classify("/v1/actors", "PUT")).toBe("method-not-allowed");
  });

  it("proxies PUT on a /v1/actors/<handle> update", () => {
    expect(classify("/v1/actors/josh", "PUT")).toBe("proxy");
  });

  it("rejects non-PUT on /v1/actors/<handle>", () => {
    expect(classify("/v1/actors/josh", "POST")).toBe("method-not-allowed");
    expect(classify("/v1/actors/josh", "GET")).toBe("method-not-allowed");
  });

  it("does NOT proxy the marketing site or ops endpoints", () => {
    expect(classify("/", "GET")).toBeNull();
    expect(classify("/index.html", "GET")).toBeNull();
    expect(classify("/etch/", "GET")).toBeNull();
    expect(classify("/city", "GET")).toBeNull();
    expect(classify("/health", "GET")).toBeNull(); // bridge ops -- not frontable
    expect(classify("/metrics", "GET")).toBeNull();
  });

  it("does NOT proxy a path that merely starts with the prefix string", () => {
    // exact-or-subpath match: /actorsfoo, /v1/actorsfoo, /blog/actors are not routes
    expect(classify("/actorsfoo", "GET")).toBeNull();
    expect(classify("/v1/actorsfoo", "POST")).toBeNull();
    expect(classify("/blog/actors-explained", "GET")).toBeNull();
    expect(classify("/.well-known/webfinger-evil", "GET")).toBeNull();
  });
});

describe("allowedMethods -- the 405 Allow header source", () => {
  it("reports the single permitted method per route", () => {
    expect(allowedMethods("/.well-known/webfinger")).toBe("GET");
    expect(allowedMethods("/v1/actors")).toBe("POST");
    expect(allowedMethods("/v1/actors/josh")).toBe("PUT");
    expect(allowedMethods("/actors")).toBe("GET");
    expect(allowedMethods("/actors/josh")).toBe("GET");
  });

  it("is empty for a non-fediverse path (never 405'd)", () => {
    expect(allowedMethods("/index.html")).toBe("");
  });
});

describe("buildForwardHeaders -- the rate-limit source-IP lock (F2)", () => {
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
