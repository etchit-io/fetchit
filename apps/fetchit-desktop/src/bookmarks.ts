// Thin wrappers over the Tauri bookmark commands. Backed by `settings.json`
// in the app-local data dir — same store as the cache policy.

import { invoke } from "@tauri-apps/api/core";
import type { Rendition } from "./types";

export interface Bookmark {
  address: string;
  label: string;
  createdAt: number;
}

export function listBookmarks(): Promise<Bookmark[]> {
  return invoke<Bookmark[]>("list_bookmarks");
}

export function isBookmarked(address: string): Promise<boolean> {
  return invoke<boolean>("is_bookmarked", { address });
}

export function addBookmark(address: string, label: string): Promise<void> {
  return invoke("add_bookmark", { address, label });
}

export function removeBookmark(address: string): Promise<void> {
  return invoke("remove_bookmark", { address });
}

/// Best-effort human-friendly title for a bookmark, falling back to the
/// address verbatim for handles and profile URIs, or a short hex slug for
/// raw content addresses.
export function deriveLabel(rendition: Rendition | null | undefined, address: string): string {
  const title = deriveTitle(rendition);
  if (title) return title;
  if (address.startsWith("@") || address.startsWith("profile:")) return address;
  return `${address.slice(0, 8)}…${address.slice(-4)}`;
}

/// Real title only — returns `null` when the rendition has no inherent
/// title. The QR-share modal uses this to decide whether to emit a
/// title row; the address-slug fallback would duplicate the abbreviated
/// address shown on the next line.
export function deriveTitle(rendition: Rendition | null | undefined): string | null {
  if (!rendition) return null;
  if (rendition.kind === "etchitEnvelope" && rendition.title) return rendition.title.trim();
  if (rendition.kind === "html") {
    const m = /<title[^>]*>([^<]+)<\/title>/i.exec(rendition.body);
    if (m && m[1]) return m[1].trim().slice(0, 80);
  }
  return null;
}
