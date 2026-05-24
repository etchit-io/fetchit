import { describe, expect, it } from "vitest";

import type { Bookmark } from "./bookmarks";
import {
  MAX_BOOKMARKS_PER_QR,
  decodeBookmarksFromShare,
  encodeBookmarksForShare,
} from "./bookmarkShare";

const ADDR_1 = "0".repeat(64);
const ADDR_2 = "1".repeat(64);
const ADDR_3 = "abcdef0123456789".repeat(4);

function bm(address: string, label: string): Bookmark {
  return { address, label, createdAt: 0 };
}

describe("encodeBookmarksForShare", () => {
  it("rejects an empty list", () => {
    expect(() => encodeBookmarksForShare([])).toThrow(/no bookmarks/);
  });

  it("rejects more than the per-QR cap", () => {
    const many = Array.from({ length: MAX_BOOKMARKS_PER_QR + 1 }, (_, i) =>
      bm(ADDR_1.slice(0, 62) + i.toString().padStart(2, "0"), `bm-${i}`),
    );
    expect(() => encodeBookmarksForShare(many)).toThrow(/cannot share more/);
  });

  it("encodes to a fetchit://import URL with v=1", () => {
    const url = encodeBookmarksForShare([bm(ADDR_1, "first")]);
    expect(url.startsWith("fetchit://import?v=1&data=")).toBe(true);
  });

  it("survives a round-trip through decode", () => {
    const original = [
      bm(ADDR_1, "first"),
      bm(ADDR_2, "second with spaces"),
      bm(ADDR_3, "💾 emoji label"),
    ];
    const url = encodeBookmarksForShare(original);
    const decoded = decodeBookmarksFromShare(url);
    expect(decoded).not.toBeNull();
    expect(decoded?.bookmarks.length).toBe(3);
    expect(decoded?.bookmarks[0].address).toBe(ADDR_1);
    expect(decoded?.bookmarks[0].label).toBe("first");
    expect(decoded?.bookmarks[2].label).toBe("💾 emoji label");
  });

  it("at the exact cap encodes successfully", () => {
    const many = Array.from({ length: MAX_BOOKMARKS_PER_QR }, (_, i) =>
      bm(ADDR_1.slice(0, 62) + i.toString().padStart(2, "0"), `bm-${i}`),
    );
    const url = encodeBookmarksForShare(many);
    const decoded = decodeBookmarksFromShare(url);
    expect(decoded?.bookmarks.length).toBe(MAX_BOOKMARKS_PER_QR);
  });
});

describe("decodeBookmarksFromShare", () => {
  it("returns null for non-fetchit URLs", () => {
    expect(decodeBookmarksFromShare("autonomi://1234")).toBeNull();
    expect(decodeBookmarksFromShare("https://example.com")).toBeNull();
  });

  it("returns null for the wrong action", () => {
    expect(
      decodeBookmarksFromShare("fetchit://something-else?v=1&data=xxx"),
    ).toBeNull();
  });

  it("returns null for an unknown version", () => {
    const url = encodeBookmarksForShare([bm(ADDR_1, "x")]);
    const tampered = url.replace("v=1", "v=99");
    expect(decodeBookmarksFromShare(tampered)).toBeNull();
  });

  it("returns null for missing data param", () => {
    expect(decodeBookmarksFromShare("fetchit://import?v=1")).toBeNull();
  });

  it("returns null for garbage in data", () => {
    expect(
      decodeBookmarksFromShare("fetchit://import?v=1&data=!!!not-base64!!!"),
    ).toBeNull();
  });

  it("skips entries whose address is not 64-hex", () => {
    // Craft a manual payload with one bad entry inline.
    const json = JSON.stringify({
      bookmarks: [
        { a: ADDR_1, l: "good" },
        { a: "nope", l: "bad" },
      ],
    });
    const b64 = btoa(json).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    const url = `fetchit://import?v=1&data=${b64}`;
    const decoded = decodeBookmarksFromShare(url);
    expect(decoded?.bookmarks.length).toBe(1);
    expect(decoded?.bookmarks[0].label).toBe("good");
  });
});
