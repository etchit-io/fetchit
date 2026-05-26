// Wire the daemon's SSE event stream — already proxied through Tauri
// as `chat:event` — into the local store.

import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { maybeNotifyInboundDm } from "./notify";
import type { ChatStore } from "./state";
import type { ChatEvent } from "./types";

export async function bindChatEvents(store: ChatStore): Promise<UnlistenFn> {
  return listen<ChatEvent>("chat:event", (ev) => {
    applyChatEvent(store, ev.payload);
  });
}

export function applyChatEvent(store: ChatStore, ev: ChatEvent): void {
  switch (ev.kind) {
    case "direct_message":
      store.recordDirectMessage(ev);
      void maybeNotifyInboundDm(store, ev);
      break;
    case "presence":
      store.applyPresenceTransition(ev);
      break;
    case "contact_added":
      store.upsertContact(ev);
      break;
    case "contact_removed":
      store.removeContact(ev.agent_id);
      break;
    default:
      break;
  }
}
