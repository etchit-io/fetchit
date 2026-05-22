// Address parsing — must match apps/fetchit-desktop/src/address.ts so the
// extension and the desktop app accept identical inputs.
//
// Two schemes route to fetch>it through the OS handler:
//   * autonomi://<64-hex>  — the network-canonical name
//   * fetchit://<64-hex>   — the brand-aliased name (same target)
// We accept either as input; downstream openers build whichever scheme they
// prefer (we default to autonomi:// for maximum interop with other clients).

const HEX_64 = /^[0-9a-fA-F]{64}$/;
const SCHEME = /^(?:autonomi|fetchit):\/\//i;
// The Autonomi app prefixes public addresses with `0x`; the address
// itself is bare 64-hex, so a leading `0x` is tolerated and dropped.
const HEX_PREFIX = /^0x/i;

export function parseAutonomiInput(raw) {
  if (typeof raw !== "string") return null;
  const a = raw.trim().replace(SCHEME, "").replace(HEX_PREFIX, "").split(/[/?#]/, 1)[0].trim();
  return HEX_64.test(a) ? a.toLowerCase() : null;
}

export function isAutonomiHref(href) {
  return typeof href === "string" && SCHEME.test(href);
}
