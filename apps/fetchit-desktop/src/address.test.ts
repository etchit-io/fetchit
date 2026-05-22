import { describe, expect, it } from "vitest";
import { parseAutonomiInput, parseAutonomiUrl } from "./address";

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

describe("parseAutonomiUrl", () => {
  it("returns the address and an empty query for a bare address", () => {
    expect(parseAutonomiUrl(HEX)).toEqual({ address: HEX, query: "" });
  });

  it("captures a query string", () => {
    expect(parseAutonomiUrl(`autonomi://${HEX}?file=abc&n=2`)).toEqual({
      address: HEX,
      query: "?file=abc&n=2",
    });
  });

  it("drops a trailing #fragment from the captured query", () => {
    expect(parseAutonomiUrl(`${HEX}?k=v#section`)).toEqual({
      address: HEX,
      query: "?k=v",
    });
  });

  it("returns null when there is no address", () => {
    expect(parseAutonomiUrl("not-an-address")).toBeNull();
  });
});
