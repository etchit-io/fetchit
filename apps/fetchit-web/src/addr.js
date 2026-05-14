// Address parsing — must match apps/fetchit-desktop/src/address.ts so the
// extension and the desktop app accept identical inputs.

const HEX_64 = /^[0-9a-fA-F]{64}$/;

export function parseAutonomiInput(raw) {
  if (typeof raw !== "string") return null;
  const a = raw.trim().replace(/^autonomi:\/\//i, "").split(/[/?#]/, 1)[0].trim();
  return HEX_64.test(a) ? a.toLowerCase() : null;
}

export function isAutonomiHref(href) {
  return typeof href === "string" && /^autonomi:\/\//i.test(href);
}
