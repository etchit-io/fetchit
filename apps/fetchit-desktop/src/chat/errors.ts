// Tauri's invoke() rejects with the value the Rust command returned in
// its Err arm. Our chat commands all do `.map_err(|e| e.to_string())`,
// so the rejected value is a String, not an Error instance. `(e as
// Error).message` on a string is undefined — fall back to coercion.

export function errMsg(e: unknown): string {
  if (e instanceof Error) return e.message || String(e);
  if (typeof e === "string") return e;
  if (e && typeof e === "object" && "message" in e) {
    return String((e as { message: unknown }).message);
  }
  try {
    return JSON.stringify(e);
  } catch {
    return String(e);
  }
}

/// Map a raw backend error string into a grandma-readable status
/// line. The backend returns `Display`-formatted Rust errors that
/// surface enum variant names, HTTP status codes, and crypto jargon
/// to the dialog — all of which read as nonsense to a non-technical
/// user. This helper pattern-matches the known shapes and substitutes
/// plain English; unmatched errors fall back to [`errMsg`] so we
/// never silently swallow a useful diagnostic.
///
/// Patterns are ordered most-specific first. Lowercase comparison so
/// the rules survive a Rust-side `Display` format change between
/// `to_string()` and `.to_string()` variants.
export function friendlyError(raw: unknown): string {
  const msg = errMsg(raw);
  const lc = msg.toLowerCase();

  // Profile / pairing
  if (lc.includes("publish your profile")) {
    // Already user-facing in chat.rs; pass through verbatim.
    return msg;
  }
  if (lc.includes("tombstoned")) {
    return "This contact has been removed from the network.";
  }
  if (lc.includes("agent_id does not match") || lc.includes("agent id does not match")) {
    return "This contact card is invalid. Ask them to share it again.";
  }
  if (lc.includes("signature verification failed")) {
    return "This contact card couldn't be verified. Ask them to share it again.";
  }

  // Relay
  if (lc.includes("relay returned 404")) {
    return "The other person hasn't published a profile yet.";
  }
  if (/relay returned 5\d\d/.test(lc)) {
    return "The chat relay is having trouble. Please try again in a moment.";
  }
  if (lc.includes("relay url must use http or https")) {
    return msg; // already clear
  }
  if (lc.includes("relay url must be a base url")) {
    return "Custom relay URL must be the base address, with no path.";
  }
  if (lc.includes("relay fetch:") || lc.includes("relay returned")) {
    return "Couldn't reach the chat relay. Check your connection and try again.";
  }

  // Chat client state
  if (lc.includes("chat layout not available")) {
    return "Chat isn't ready yet. Please wait a moment and try again.";
  }
  if (lc.includes("invalid relay url")) {
    return "That doesn't look like a valid URL.";
  }

  // Card import
  if (lc.includes("expected value at line")) {
    return "Couldn't read that card — it may be corrupted or for an older version.";
  }
  if (lc.includes("invalid card")) {
    return "That card isn't valid. Ask the sender to share again.";
  }

  // Unmatched errors: raw Rust `Display` output (type names, nested
  // sources) reads as noise to a person. Pass through short plain
  // sentences; route anything structured to the console and show a
  // friendly line instead — never silently swallow.
  if (msg.length <= 90 && !msg.includes("(")) {
    return msg;
  }
  console.warn("[chat] unmapped error:", msg);
  return "Something went wrong. Try again in a moment.";
}
