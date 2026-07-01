import { describe, expect, it } from "vitest";
import { resolveProfile, relayFromShareUri } from "./open";
import type { ProfilePageModel } from "./open";

const VERIFIED = {
  kind: "verified" as const,
  handle: "@josh@etchit.io",
  actorUrl: "https://etchit.io/actors/josh",
  agentIdHex: "a".repeat(64),
  displayName: "Josh",
  bio: "hi",
  avatar: null,
  shareUri: `fetchit://share/v3/${"a".repeat(64)}/${"c".repeat(64)}?relay=https://r.example/`,
  previousAgentIdHex: null,
  verifyFailure: null,
};
const PROFILE_OUTCOME = {
  kind: "profile" as const,
  displayName: "Josh",
  bio: "hi",
  website: "https://tankcheck.net",
  links: [{ kind: "etchit", label: "showcase", addr: "d".repeat(64) }],
  avatar: null,
  issuedAtMs: 1,
};

describe("relayFromShareUri", () => {
  it("extracts the relay from a v3 share uri", () => {
    expect(relayFromShareUri(VERIFIED.shareUri)).toBe("https://r.example/");
    expect(relayFromShareUri("garbage")).toBeNull();
  });
});

describe("resolveProfile", () => {
  it("merges lookup identity with manifest links for a verified handle", async () => {
    const m: ProfilePageModel = await resolveProfile(
      { kind: "handle", handle: "@josh@etchit.io" },
      { lookupHandle: async () => VERIFIED, fetchProfile: async () => PROFILE_OUTCOME },
    );
    expect(m.state).toBe("verified");
    expect(m.verified).toBe(true);
    expect(m.handle).toBe("@josh@etchit.io");
    expect(m.website).toBe("https://tankcheck.net");
    expect(m.links).toHaveLength(1);
    expect(m.shareUri).toBe(VERIFIED.shareUri);
  });

  it("renders public-only with a visible failure and no private fields", async () => {
    const m = await resolveProfile(
      { kind: "handle", handle: "@x@y.io" },
      {
        lookupHandle: async () => ({ ...VERIFIED, kind: "publicOnly" as const, agentIdHex: null, shareUri: null, verifyFailure: "bad sig" }),
        fetchProfile: async () => { throw new Error("must not be called"); },
      },
    );
    expect(m.state).toBe("publicOnly");
    expect(m.verified).toBe(false);
    expect(m.verifyFailure).toBe("bad sig");
    expect(m.shareUri).toBeNull();
  });

  it("flags changed-hands from the continuity ledger", async () => {
    const m = await resolveProfile(
      { kind: "handle", handle: "@josh@etchit.io" },
      { lookupHandle: async () => ({ ...VERIFIED, previousAgentIdHex: "f".repeat(64) }), fetchProfile: async () => PROFILE_OUTCOME },
    );
    expect(m.changedHands).toBe(true);
  });

  it("resolves an agent-id contact via chat_fetch_profile alone", async () => {
    const m = await resolveProfile(
      { kind: "agentId", agentId: "a".repeat(64), isSelf: true },
      { lookupHandle: async () => { throw new Error("must not be called"); }, fetchProfile: async () => PROFILE_OUTCOME },
    );
    expect(m.state).toBe("verified");
    expect(m.isSelf).toBe(true);
    expect(m.handle).toBeNull();
    expect(m.links).toHaveLength(1);
  });

  it("returns none when an agent-id contact has not published", async () => {
    const m = await resolveProfile(
      { kind: "agentId", agentId: "a".repeat(64), isSelf: true },
      { lookupHandle: async () => { throw new Error("nope"); }, fetchProfile: async () => ({ kind: "none" }) },
    );
    expect(m.state).toBe("none");
  });
});
