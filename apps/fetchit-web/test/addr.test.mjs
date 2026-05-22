// Tests for the address parser shared between the extension's background
// service worker, its content script, and (mirrored) the desktop app's
// own address parsing. Uses Node's built-in test runner — no deps:
//
//   node --test apps/fetchit-web/test/addr.test.mjs
//
// The parser MUST accept the same inputs the desktop app accepts and reject
// the same inputs the desktop app rejects, byte for byte. If you change one
// side, change both — the extension routes addresses to the desktop, so
// divergence shows up as "address that worked in fetch>it doesn't work
// from the extension" (or vice versa).

import { test } from "node:test";
import assert from "node:assert/strict";
import { parseAutonomiInput, parseAutonomiUrl, isAutonomiHref } from "../src/addr.js";

const HEX64 =
  "bebb4f16bc23aa4581bff5fec471829959c1edbe4485eb4cf0d853a62f5406f0";
const HEX64_UPPER = HEX64.toUpperCase();

test("parseAutonomiInput — bare hex address", () => {
  assert.equal(parseAutonomiInput(HEX64), HEX64);
});

test("parseAutonomiInput — autonomi:// prefix is stripped", () => {
  assert.equal(parseAutonomiInput(`autonomi://${HEX64}`), HEX64);
});

test("parseAutonomiInput — fetchit:// prefix is stripped (brand alias)", () => {
  // Both schemes route to fetch>it via the OS handler; the parser
  // accepts either and returns the bare hex address.
  assert.equal(parseAutonomiInput(`fetchit://${HEX64}`), HEX64);
  assert.equal(parseAutonomiInput(`FETCHIT://${HEX64}`), HEX64);
  assert.equal(parseAutonomiInput(`Fetchit://${HEX64}`), HEX64);
});

test("parseAutonomiInput — fetchit:// with path / query / fragment", () => {
  assert.equal(parseAutonomiInput(`fetchit://${HEX64}/page.html`), HEX64);
  assert.equal(parseAutonomiInput(`fetchit://${HEX64}?k=v`), HEX64);
  assert.equal(parseAutonomiInput(`fetchit://${HEX64}#x`), HEX64);
});

test("parseAutonomiInput — uppercase scheme is case-insensitive", () => {
  assert.equal(parseAutonomiInput(`AUTONOMI://${HEX64}`), HEX64);
  assert.equal(parseAutonomiInput(`Autonomi://${HEX64}`), HEX64);
});

test("parseAutonomiInput — uppercase hex is lowercased", () => {
  assert.equal(parseAutonomiInput(HEX64_UPPER), HEX64);
  assert.equal(parseAutonomiInput(`autonomi://${HEX64_UPPER}`), HEX64);
});

test("parseAutonomiInput — path component is dropped", () => {
  assert.equal(parseAutonomiInput(`autonomi://${HEX64}/page.html`), HEX64);
  assert.equal(parseAutonomiInput(`autonomi://${HEX64}/a/b/c`), HEX64);
});

test("parseAutonomiInput — query and fragment dropped", () => {
  assert.equal(parseAutonomiInput(`autonomi://${HEX64}?key=value`), HEX64);
  assert.equal(parseAutonomiInput(`autonomi://${HEX64}#section`), HEX64);
  assert.equal(parseAutonomiInput(`autonomi://${HEX64}?a=1#x`), HEX64);
});

test("parseAutonomiInput — surrounding whitespace trimmed", () => {
  assert.equal(parseAutonomiInput(`  ${HEX64}  `), HEX64);
  assert.equal(parseAutonomiInput(`\t${HEX64}\n`), HEX64);
  assert.equal(parseAutonomiInput(`  autonomi://${HEX64}  `), HEX64);
});

test("parseAutonomiInput — wrong length returns null", () => {
  assert.equal(parseAutonomiInput("abc"), null);
  assert.equal(parseAutonomiInput(HEX64.slice(0, 63)), null);
  assert.equal(parseAutonomiInput(HEX64 + "0"), null);
});

test("parseAutonomiInput — non-hex characters return null", () => {
  // Same length as HEX64 but contains 'g' — outside hex range.
  const notHex = "g".repeat(64);
  assert.equal(parseAutonomiInput(notHex), null);
});

test("parseAutonomiInput — leading 0x prefix is stripped", () => {
  // The Autonomi app prefixes public addresses with `0x`; the address
  // itself is bare 64-hex, so the parser tolerates and drops it.
  assert.equal(parseAutonomiInput(`0x${HEX64}`), HEX64);
  assert.equal(parseAutonomiInput(`0X${HEX64}`), HEX64);
});

test("parseAutonomiInput — non-string inputs return null", () => {
  assert.equal(parseAutonomiInput(null), null);
  assert.equal(parseAutonomiInput(undefined), null);
  assert.equal(parseAutonomiInput(123), null);
  assert.equal(parseAutonomiInput({}), null);
  assert.equal(parseAutonomiInput([]), null);
});

test("parseAutonomiInput — empty string returns null", () => {
  assert.equal(parseAutonomiInput(""), null);
  assert.equal(parseAutonomiInput("   "), null);
});

test("parseAutonomiInput — extra junk after address returns null", () => {
  // The parser strips ?, #, / — anything else trailing is a mismatch.
  assert.equal(parseAutonomiInput(`${HEX64} extra`), null);
  assert.equal(parseAutonomiInput(`${HEX64}.png`), null);
});

test("isAutonomiHref — accepts both cases of autonomi://", () => {
  assert.equal(isAutonomiHref(`autonomi://${HEX64}`), true);
  assert.equal(isAutonomiHref(`AUTONOMI://${HEX64}`), true);
  assert.equal(isAutonomiHref(`autonomi://${HEX64}/path?q#f`), true);
});

test("isAutonomiHref — accepts fetchit:// (brand alias)", () => {
  assert.equal(isAutonomiHref(`fetchit://${HEX64}`), true);
  assert.equal(isAutonomiHref(`FETCHIT://${HEX64}`), true);
  assert.equal(isAutonomiHref(`Fetchit://${HEX64}/path?q#f`), true);
});

test("isAutonomiHref — rejects non-routing schemes", () => {
  assert.equal(isAutonomiHref(`https://${HEX64}`), false);
  assert.equal(isAutonomiHref(`ipfs://${HEX64}`), false);
  assert.equal(isAutonomiHref(HEX64), false);
  assert.equal(isAutonomiHref("javascript:alert(1)"), false);
});

test("isAutonomiHref — rejects non-string inputs", () => {
  assert.equal(isAutonomiHref(null), false);
  assert.equal(isAutonomiHref(undefined), false);
  assert.equal(isAutonomiHref(123), false);
});

test("parseAutonomiUrl — bare address, empty query", () => {
  assert.deepEqual(parseAutonomiUrl(HEX64), { address: HEX64, query: "" });
});

test("parseAutonomiUrl — captures a query string", () => {
  assert.deepEqual(parseAutonomiUrl(`autonomi://${HEX64}?file=a&n=2`), {
    address: HEX64,
    query: "?file=a&n=2",
  });
});

test("parseAutonomiUrl — fetchit:// scheme, with query", () => {
  assert.deepEqual(parseAutonomiUrl(`fetchit://${HEX64}?k=v`), {
    address: HEX64,
    query: "?k=v",
  });
});

test("parseAutonomiUrl — 0x prefix stripped, query kept", () => {
  assert.deepEqual(parseAutonomiUrl(`0x${HEX64}?k=v`), {
    address: HEX64,
    query: "?k=v",
  });
});

test("parseAutonomiUrl — uppercase hex is lowercased", () => {
  assert.deepEqual(parseAutonomiUrl(`${HEX64_UPPER}?k=v`), {
    address: HEX64,
    query: "?k=v",
  });
});

test("parseAutonomiUrl — trailing #fragment dropped from the query", () => {
  assert.deepEqual(parseAutonomiUrl(`${HEX64}?k=v#section`), {
    address: HEX64,
    query: "?k=v",
  });
});

test("parseAutonomiUrl — a ? inside the fragment is not a query", () => {
  assert.deepEqual(parseAutonomiUrl(`${HEX64}#frag?notquery`), {
    address: HEX64,
    query: "",
  });
});

test("parseAutonomiUrl — invalid address returns null", () => {
  assert.equal(parseAutonomiUrl("not-an-address"), null);
  assert.equal(parseAutonomiUrl(HEX64.slice(0, 63)), null);
  assert.equal(parseAutonomiUrl(null), null);
});
