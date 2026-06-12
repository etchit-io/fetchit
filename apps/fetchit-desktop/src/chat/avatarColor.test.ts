import { describe, it, expect } from "vitest";
import { avatarGradientClass } from "./avatarColor";

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
