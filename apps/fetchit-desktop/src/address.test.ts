import { describe, expect, it } from "vitest";
import { parseAutonomiInput } from "./address";

const HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

describe("parseAutonomiInput", () => {
  it("accepts a bare 64-hex string", () => {
    expect(parseAutonomiInput(HEX)).toBe(HEX);
  });

  it("strips a leading autonomi:// prefix", () => {
    expect(parseAutonomiInput(`autonomi://${HEX}`)).toBe(HEX);
  });

  it("strips a leading 0x prefix", () => {
    expect(parseAutonomiInput(`0x${HEX}`)).toBe(HEX);
    expect(parseAutonomiInput(`0X${HEX}`)).toBe(HEX);
  });

  it("matches the prefix case-insensitively", () => {
    expect(parseAutonomiInput(`AUTONOMI://${HEX}`)).toBe(HEX);
  });

  it("trims surrounding whitespace", () => {
    expect(parseAutonomiInput(`  ${HEX}  `)).toBe(HEX);
  });

  it("accepts uppercase hex", () => {
    const upper = HEX.toUpperCase();
    expect(parseAutonomiInput(upper)).toBe(upper);
  });

  it("ignores trailing path / query / fragment", () => {
    expect(parseAutonomiInput(`autonomi://${HEX}/nested.html`)).toBe(HEX);
    expect(parseAutonomiInput(`autonomi://${HEX}?x=1`)).toBe(HEX);
    expect(parseAutonomiInput(`autonomi://${HEX}#frag`)).toBe(HEX);
  });

  it("rejects strings of the wrong length", () => {
    expect(parseAutonomiInput(HEX.slice(0, 63))).toBeNull();
    expect(parseAutonomiInput(`${HEX}0`)).toBeNull();
  });

  it("rejects non-hex characters", () => {
    const bad = "z".repeat(64);
    expect(parseAutonomiInput(bad)).toBeNull();
  });

  it("rejects the empty string", () => {
    expect(parseAutonomiInput("")).toBeNull();
    expect(parseAutonomiInput("   ")).toBeNull();
  });
});
