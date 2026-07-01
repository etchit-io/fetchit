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

/** A pasted/typed address resolved to one of the reader's input classes. */
export type AddressInput =
  | { kind: "hex"; address: string; query: string }
  | { kind: "handle"; handle: string }
  | { kind: "profile"; agentId: string };

const HANDLE_INPUT = /^@[^@\s]+@[^@\s]+\.[^@\s]+$/;
const PROFILE_INPUT = /^profile:([0-9a-fA-F]{64})$/;

/**
 * Classify an address-bar input. Bare 64-hex is always an Autonomi
 * content address (hex); an agent-id profile uses the explicit
 * `profile:` prefix, so the two never collide. Handles are lowercased
 * (the registry is lowercase-canonical).
 */
export function parseAddressInput(raw: string): AddressInput | null {
  const t = raw.trim();
  const prof = PROFILE_INPUT.exec(t);
  if (prof) return { kind: "profile", agentId: prof[1].toLowerCase() };
  const lower = t.toLowerCase();
  if (HANDLE_INPUT.test(lower)) return { kind: "handle", handle: lower };
  const hex = parseAutonomiUrl(t);
  if (hex) return { kind: "hex", address: hex.address, query: hex.query };
  return null;
}
