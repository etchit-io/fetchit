// Encodes a list of bookmarks into a `fetchit://import?…` URL the Android
// app's deep-link handler picks up off a scanned QR. Format:
//
//   fetchit://import?v=1&data=<base64url-encoded-JSON>
//
// where the JSON is `{"bookmarks":[{"a":"<64hex>","l":"<label>"}, ...]}`.
//
// Capped at MAX_BOOKMARKS_PER_QR so the encoded URL stays inside a
// standard QR code's binary-mode capacity (~2.3 KB at version 40, ECC
// level M, with safety margin for typical label lengths).

import type { Bookmark } from "./bookmarks";

/** Hard ceiling so we don't generate a QR the scanner can't read. */
export const MAX_BOOKMARKS_PER_QR = 20;

/** Wire shape for a single bookmark in the share payload. Compact keys
 *  keep the URL short. */
interface SharedBookmark {
  /** 64-character lowercase-hex Autonomi address. */
  a: string;
  /** Human-readable label. */
  l: string;
}

interface SharePayload {
  bookmarks: SharedBookmark[];
}

/** Build the `fetchit://import?…` URL for `bookmarks`.
 *
 *  Throws if the list is empty or exceeds MAX_BOOKMARKS_PER_QR — both
 *  cases are caller-error and should be surfaced to the user instead
 *  of silently producing an unscannable QR. */
export function encodeBookmarksForShare(bookmarks: Bookmark[]): string {
  if (bookmarks.length === 0) {
    throw new Error("no bookmarks to share");
  }
  if (bookmarks.length > MAX_BOOKMARKS_PER_QR) {
    throw new Error(
      `cannot share more than ${MAX_BOOKMARKS_PER_QR} bookmarks in one QR (got ${bookmarks.length})`,
    );
  }
  const payload: SharePayload = {
    bookmarks: bookmarks.map((bm) => ({ a: bm.address, l: bm.label })),
  };
  const json = JSON.stringify(payload);
  const bytes = new TextEncoder().encode(json);
  return `fetchit://import?v=1&data=${bytesToBase64Url(bytes)}`;
}

/** Parse a `fetchit://import?…` URL back into bookmarks. Used by tests
 *  here to round-trip-verify the format the Android side will see.
 *  Returns null on any decode error so callers can fall back cleanly. */
export function decodeBookmarksFromShare(
  url: string,
): { bookmarks: Bookmark[] } | null {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "fetchit:" || parsed.host !== "import") {
      return null;
    }
    if (parsed.searchParams.get("v") !== "1") {
      return null;
    }
    const data = parsed.searchParams.get("data");
    if (!data) {
      return null;
    }
    const bytes = base64UrlToBytes(data);
    const json = new TextDecoder().decode(bytes);
    const payload = JSON.parse(json) as SharePayload;
    if (!payload || !Array.isArray(payload.bookmarks)) {
      return null;
    }
    // `createdAt: 0` — the receiver fills in its own timestamp on
    // import, the sender's local createdAt is meaningless on a fresh
    // device.
    const bookmarks: Bookmark[] = payload.bookmarks
      .filter((b): b is SharedBookmark => isValidShared(b))
      .map((b) => ({ address: b.a, label: b.l, createdAt: 0 }));
    return { bookmarks };
  } catch {
    return null;
  }
}

function isValidShared(b: unknown): b is SharedBookmark {
  if (typeof b !== "object" || b === null) return false;
  const obj = b as Record<string, unknown>;
  if (typeof obj.a !== "string" || typeof obj.l !== "string") return false;
  return /^[0-9a-f]{64}$/.test(obj.a);
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function base64UrlToBytes(b64url: string): Uint8Array {
  const padded =
    b64url.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - (b64url.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
