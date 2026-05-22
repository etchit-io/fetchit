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

// Parse an input into its bare address and query string. Tolerates a
// scheme prefix, a leading `0x`, whitespace, and a trailing path /
// `#fragment`; returns null when the leading segment isn't 64-hex. The
// query (with its `?`) is kept so it can be routed on to the desktop.
export function parseAutonomiUrl(raw) {
  if (typeof raw !== "string") return null;
  const cleaned = raw.trim().replace(SCHEME, "").replace(HEX_PREFIX, "");
  const address = cleaned.split(/[/?#]/, 1)[0].trim();
  if (!HEX_64.test(address)) return null;
  const hash = cleaned.indexOf("#");
  const q = cleaned.indexOf("?");
  // A `?` only opens a query when it precedes any `#`.
  const query =
    q < 0 || (hash >= 0 && hash < q)
      ? ""
      : cleaned.slice(q, hash < 0 ? undefined : hash);
  return { address: address.toLowerCase(), query };
}

// The bare 64-hex address from an input, or null.
export function parseAutonomiInput(raw) {
  return parseAutonomiUrl(raw)?.address ?? null;
}

export function isAutonomiHref(href) {
  return typeof href === "string" && SCHEME.test(href);
}
