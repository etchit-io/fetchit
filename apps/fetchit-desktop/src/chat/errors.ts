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
