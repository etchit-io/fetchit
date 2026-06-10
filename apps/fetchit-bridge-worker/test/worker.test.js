import { describe, it, expect } from "vitest";
import { classify } from "../src/worker.js";

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
