export function parseAutonomiInput(raw: string): string | null {
  const a = raw.trim().replace(/^autonomi:\/\//i, "").split(/[/?#]/, 1)[0].trim();
  return /^[0-9a-fA-F]{64}$/.test(a) ? a : null;
}
