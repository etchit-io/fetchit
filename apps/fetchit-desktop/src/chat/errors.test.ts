import { describe, expect, it } from "vitest";
import { errMsg, friendlyError } from "./errors";

describe("errMsg", () => {
  it("returns Error.message", () => {
    expect(errMsg(new Error("boom"))).toBe("boom");
  });

  it("returns string values as-is", () => {
    expect(errMsg("daemon offline")).toBe("daemon offline");
  });

  it("unwraps objects with a message field", () => {
    expect(errMsg({ message: "remote rejected" })).toBe("remote rejected");
  });

  it("falls back to JSON-stringify for plain objects", () => {
    expect(errMsg({ code: 42 })).toBe('{"code":42}');
  });

  it("survives a non-serialisable value", () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(typeof errMsg(cyclic)).toBe("string");
  });
});

describe("friendlyError", () => {
  // The whole point of this helper is grandma-readable copy — pin
  // each substitution so a future Rust-side rename doesn't silently
  // surface a Rust enum variant to the dialog.

  it("substitutes the tombstoned profile error", () => {
    expect(friendlyError("offerer's profile was tombstoned"))
      .toBe("This contact has been removed from the network.");
  });

  it("substitutes the agent_id-mismatch error", () => {
    expect(
      friendlyError("URI agent_id does not match relay record"),
    ).toBe("This contact card is invalid. Ask them to share it again.");
  });

  it("substitutes the signature-failure error", () => {
    expect(friendlyError("signature verification failed"))
      .toBe(
        "This contact card couldn't be verified. Ask them to share it again.",
      );
  });

  it("substitutes 404 from the relay with 'hasn't published'", () => {
    expect(friendlyError("relay returned 404"))
      .toBe("The other person hasn't published a profile yet.");
  });

  it("substitutes any 5xx into a 'relay having trouble' line", () => {
    expect(friendlyError("relay returned 500"))
      .toContain("trouble");
    expect(friendlyError("relay returned 503"))
      .toContain("trouble");
  });

  it("passes through the already-user-facing 'Publish your profile first' message", () => {
    expect(
      friendlyError(
        "Publish your profile first — open the Profile tab in etch>it and click Publish.",
      ),
    ).toContain("Publish your profile");
  });

  it("substitutes the 'chat layout not available' message", () => {
    expect(
      friendlyError("chat layout not available (REST-only client)"),
    ).toBe("Chat isn't ready yet. Please wait a moment and try again.");
  });

  it("substitutes 'expected value at line' (JSON decode) into card-corruption copy", () => {
    expect(
      friendlyError("expected value at line 1 column 1"),
    ).toContain("corrupted");
  });

  it("substitutes 'invalid relay url' into plain-English copy", () => {
    expect(friendlyError("invalid relay url: bad scheme"))
      .toBe("That doesn't look like a valid URL.");
  });

  it("substitutes the no-path rule", () => {
    expect(
      friendlyError("relay url must be a base URL with no path"),
    ).toContain("base address");
  });

  it("falls back to errMsg on unknown strings", () => {
    expect(friendlyError("totally novel failure mode 9000"))
      .toBe("totally novel failure mode 9000");
  });

  it("falls back to errMsg on Error instances with unknown content", () => {
    expect(friendlyError(new Error("very specific niche error"))).toBe(
      "very specific niche error",
    );
  });
});
