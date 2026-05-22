const HEX_64 = /^[0-9a-fA-F]{64}$/;

/** A parsed `autonomi://` input — the address and its optional query. */
export interface AutonomiUrl {
  /** The bare 64-hex address. */
  address: string;
  /** The query string including its leading `?`, or `""` if none. */
  query: string;
}

/**
 * Parse a pasted `autonomi://` input into its address and query string.
 * Tolerates a leading `autonomi://` scheme, a leading `0x`, surrounding
 * whitespace, and a trailing path / `#fragment`. Returns `null` when the
 * leading segment is not a 64-hex address.
 */
export function parseAutonomiUrl(raw: string): AutonomiUrl | null {
  const cleaned = raw
    .trim()
    .replace(/^autonomi:\/\//i, "")
    // The Autonomi app prefixes public addresses with `0x`; drop it.
    .replace(/^0x/i, "");
  const address = cleaned.split(/[/?#]/, 1)[0].trim();
  if (!HEX_64.test(address)) return null;
  const hash = cleaned.indexOf("#");
  const q = cleaned.indexOf("?");
  // A `?` only opens a query when it precedes any `#`.
  if (q < 0 || (hash >= 0 && hash < q)) return { address, query: "" };
  const query = cleaned.slice(q, hash < 0 ? undefined : hash);
  return { address, query };
}

/** The bare 64-hex address from a pasted input, or `null`. */
export function parseAutonomiInput(raw: string): string | null {
  return parseAutonomiUrl(raw)?.address ?? null;
}
