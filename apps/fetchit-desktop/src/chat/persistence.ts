// localStorage layer for chat state that the daemon does not retain.
// Currently: DM transcripts keyed by the local agent identity. Group
// history is fetched from the daemon, so only DMs persist here.

import type { AgentId } from "./types";
import type { ChatBubble } from "./state";

const STORAGE_VERSION = 1;

/// Per-peer transcript cap. Oldest bubbles are dropped when exceeded.
export const MAX_BUBBLES_PER_DM = 1000;

export interface PersistedDm {
  messages: ChatBubble[];
  unread: number;
  lastActivityMs: number;
}

interface PersistedState {
  version: number;
  dms: Record<AgentId, PersistedDm>;
}

const storageKey = (myId: AgentId): string => `fetchit-chat:dms:${myId}`;

export function loadDms(myId: AgentId): Map<AgentId, PersistedDm> {
  try {
    const raw = readItem(storageKey(myId));
    if (!raw) return new Map();
    const parsed = JSON.parse(raw) as PersistedState;
    if (parsed?.version !== STORAGE_VERSION) return new Map();
    return new Map(Object.entries(parsed.dms ?? {}));
  } catch (e) {
    console.warn("[chat] hydrate failed:", e);
    return new Map();
  }
}

export function saveDms(
  myId: AgentId,
  dms: Map<AgentId, PersistedDm>,
): void {
  try {
    const obj: Record<AgentId, PersistedDm> = {};
    for (const [peer, dm] of dms) {
      obj[peer] = {
        messages: dm.messages.slice(-MAX_BUBBLES_PER_DM),
        unread: dm.unread,
        lastActivityMs: dm.lastActivityMs,
      };
    }
    const state: PersistedState = { version: STORAGE_VERSION, dms: obj };
    writeItem(storageKey(myId), JSON.stringify(state));
  } catch (e) {
    console.warn("[chat] persist failed:", e);
  }
}

export function clearDms(myId: AgentId): void {
  try {
    removeItem(storageKey(myId));
  } catch {
    // ignore
  }
}

// localStorage wrappers — keep one shape across the module so a future
// switch to IndexedDB or Tauri-backed storage touches one place.
function readItem(key: string): string | null {
  if (typeof localStorage === "undefined") return null;
  return localStorage.getItem(key);
}
function writeItem(key: string, value: string): void {
  if (typeof localStorage === "undefined") return;
  localStorage.setItem(key, value);
}
function removeItem(key: string): void {
  if (typeof localStorage === "undefined") return;
  localStorage.removeItem(key);
}
