export function parseAutonomiInput(raw: string): string | null {
  // A leading `0x` is tolerated and dropped — the Autonomi app prefixes
  // public addresses with it; the address itself is bare 64-hex.
  const a = raw
    .trim()
    .replace(/^autonomi:\/\//i, "")
    .replace(/^0x/i, "")
    .split(/[/?#]/, 1)[0]
    .trim();
  return /^[0-9a-fA-F]{64}$/.test(a) ? a : null;
}
