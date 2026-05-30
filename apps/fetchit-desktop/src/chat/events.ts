// Wire the daemon's SSE event stream — already proxied through Tauri
// as `chat:event` — into the local store.

import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { maybeNotifyInboundDm } from "./notify";
import type { ChatStore, DaemonStatus, NearbyPeer } from "./state";
import type { ChatEvent } from "./types";

/// Wire-shape of the daemon's `chat:receipt` Tauri event.
interface ReceiptEvent {
  group_id: string;
  sender: string;
  message_id: string;
  received_at_ms: number;
}

/// Wire-shape of the daemon's `chat:presence` Tauri event (relay source).
interface RelayPresenceEvent {
  source: "relay";
  agent_id: string;
  online: boolean;
}

/// Wire-shape of the daemon's `chat:nearby` Tauri event — periodic
/// snapshot of the LAN-direct peer table. Empty when LAN delivery is
/// disabled.
interface NearbyEventPeer {
  agentId: string;
  ip: string;
  port: number;
  lastSeenMsAgo: number;
}

export async function bindChatEvents(store: ChatStore): Promise<UnlistenFn> {
  const unsubEvent = await listen<ChatEvent>("chat:event", (ev) => {
    applyChatEvent(store, ev.payload);
  });
  const unsubReceipt = await listen<ReceiptEvent>("chat:receipt", (ev) => {
    store.markDelivered(ev.payload.sender, ev.payload.message_id);
  });
  const unsubPresence = await listen<RelayPresenceEvent>(
    "chat:presence",
    (ev) => {
      store.setRelayPresence(ev.payload.agent_id, ev.payload.online);
    },
  );
  const unsubNearby = await listen<NearbyEventPeer[]>("chat:nearby", (ev) => {
    const peers: NearbyPeer[] = (ev.payload ?? []).map((p) => ({
      agentId: p.agentId,
      ip: p.ip,
      port: p.port,
      lastSeenMsAgo: p.lastSeenMsAgo,
    }));
    store.setNearbyPeers(peers);
  });
  const unsubDaemon = await listen<DaemonStatus>(
    "chat:daemon-status",
    (ev) => {
      store.setDaemonStatus(ev.payload);
    },
  );
  return () => {
    unsubEvent();
    unsubReceipt();
    unsubPresence();
    unsubNearby();
    unsubDaemon();
  };
}

export function applyChatEvent(store: ChatStore, ev: ChatEvent): void {
  switch (ev.kind) {
    case "direct_message":
      store.recordDirectMessage(ev);
      void maybeNotifyInboundDm(store, ev);
      break;
    case "presence":
      // The legacy x0xd presence stream is now emitted as
      // `chat:presence:x0x` to leave `chat:presence` for the
      // authoritative relay-level signal. Drop it on the floor here;
      // the relay dot is the one we paint.
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
