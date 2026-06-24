import { describe, it, expect } from "vitest";
import {
  avatarGradientClass,
  bubbleIdentityClass,
  initials,
  senderIdentityClass,
} from "./avatarColor";

describe("initials", () => {
  it("takes the first letter of the first two words", () => {
    expect(initials("Ada Lovelace")).toBe("AL");
    expect(initials("  grace   hopper  ")).toBe("GH");
  });
  it("takes the first two letters of a single word", () => {
    expect(initials("Mononym")).toBe("MO");
  });
  it("falls back to a question mark for an empty name", () => {
    expect(initials("")).toBe("?");
    expect(initials("   ")).toBe("?");
  });
});

describe("avatarGradientClass", () => {
  it("is deterministic for the same agent id", () => {
    const id = "ab".repeat(32);
    expect(avatarGradientClass(id)).toBe(avatarGradientClass(id));
  });
  it("maps the first byte modulo 8", () => {
    expect(avatarGradientClass("00" + "11".repeat(31))).toBe("chat-avatar--g0");
    expect(avatarGradientClass("07" + "11".repeat(31))).toBe("chat-avatar--g7");
    expect(avatarGradientClass("0f" + "11".repeat(31))).toBe("chat-avatar--g7");
    expect(avatarGradientClass("10" + "11".repeat(31))).toBe("chat-avatar--g0");
  });
  it("falls back to g0 on malformed input", () => {
    expect(avatarGradientClass("")).toBe("chat-avatar--g0");
    expect(avatarGradientClass("zz")).toBe("chat-avatar--g0");
  });
});

describe("bubbleIdentityClass", () => {
  it("shares the avatar's index so a person's avatar and bubble match", () => {
    const id = "07" + "11".repeat(31);
    expect(bubbleIdentityClass(id)).toBe("chat-bubble--id7");
    expect(avatarGradientClass(id)).toBe("chat-avatar--g7");
  });
  it("maps the first byte modulo 8", () => {
    expect(bubbleIdentityClass("00" + "11".repeat(31))).toBe("chat-bubble--id0");
    expect(bubbleIdentityClass("10" + "11".repeat(31))).toBe("chat-bubble--id0");
    expect(bubbleIdentityClass("0f" + "11".repeat(31))).toBe("chat-bubble--id7");
  });
  it("falls back to id0 on malformed input", () => {
    expect(bubbleIdentityClass("")).toBe("chat-bubble--id0");
  });
});

describe("senderIdentityClass", () => {
  it("shares the avatar and bubble index so name, avatar and stripe match", () => {
    const id = "07" + "11".repeat(31);
    expect(senderIdentityClass(id)).toBe("chat-sender--id7");
    expect(bubbleIdentityClass(id)).toBe("chat-bubble--id7");
    expect(avatarGradientClass(id)).toBe("chat-avatar--g7");
  });
  it("maps the first byte modulo 8", () => {
    expect(senderIdentityClass("00" + "11".repeat(31))).toBe("chat-sender--id0");
    expect(senderIdentityClass("0f" + "11".repeat(31))).toBe("chat-sender--id7");
  });
  it("falls back to id0 on malformed input", () => {
    expect(senderIdentityClass("")).toBe("chat-sender--id0");
  });
});
