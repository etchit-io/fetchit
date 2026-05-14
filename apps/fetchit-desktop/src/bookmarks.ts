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

/// Best-effort human-friendly title for a bookmark — falls back to a short
/// address slug when no title is present in the rendition.
export function deriveLabel(rendition: Rendition | null | undefined, address: string): string {
  if (rendition) {
    if (rendition.kind === "etchitEnvelope" && rendition.title) return rendition.title.trim();
    if (rendition.kind === "html") {
      const m = /<title[^>]*>([^<]+)<\/title>/i.exec(rendition.body);
      if (m && m[1]) return m[1].trim().slice(0, 80);
    }
  }
  return `${address.slice(0, 8)}…${address.slice(-4)}`;
}
