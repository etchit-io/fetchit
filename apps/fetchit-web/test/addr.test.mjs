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
import { parseAutonomiInput, isAutonomiHref } from "../src/addr.js";

const HEX64 =
  "bebb4f16bc23aa4581bff5fec471829959c1edbe4485eb4cf0d853a62f5406f0";
const HEX64_UPPER = HEX64.toUpperCase();

test("parseAutonomiInput — bare hex address", () => {
  assert.equal(parseAutonomiInput(HEX64), HEX64);
});

test("parseAutonomiInput — autonomi:// prefix is stripped", () => {
  assert.equal(parseAutonomiInput(`autonomi://${HEX64}`), HEX64);
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
  // 0x prefix is intentionally NOT stripped — Autonomi addresses are bare
  // hex, not Ethereum-style. If a user pastes `0x<hex>` it's invalid input.
  assert.equal(parseAutonomiInput(`0x${HEX64}`), null);
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

test("isAutonomiHref — accepts both cases", () => {
  assert.equal(isAutonomiHref(`autonomi://${HEX64}`), true);
  assert.equal(isAutonomiHref(`AUTONOMI://${HEX64}`), true);
  assert.equal(isAutonomiHref(`autonomi://${HEX64}/path?q#f`), true);
});

test("isAutonomiHref — rejects non-autonomi schemes", () => {
  assert.equal(isAutonomiHref(`https://${HEX64}`), false);
  assert.equal(isAutonomiHref(HEX64), false);
  assert.equal(isAutonomiHref("javascript:alert(1)"), false);
});

test("isAutonomiHref — rejects non-string inputs", () => {
  assert.equal(isAutonomiHref(null), false);
  assert.equal(isAutonomiHref(undefined), false);
  assert.equal(isAutonomiHref(123), false);
});
