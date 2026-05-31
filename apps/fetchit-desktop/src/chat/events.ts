// Wire the daemon's SSE event stream — already proxied through Tauri
// as `chat:event` — into the local store.

import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { maybeNotifyInboundDm } from "./notify";
import type { ChatStore, DaemonStatus, NearbyPeer, PendingContact } from "./state";
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

/// Wire-shape of the daemon's `chat:contact-request` Tauri event —
/// the full `fetchit_chat::conversation::Conversation` serialized as
/// JSON. We only read the fields the dialog needs.
interface ContactRequestEvent {
  group_id_hex: string;
  members: Array<{
    devices?: Array<{ agent_id_hex?: string }>;
  }>;
}

/// Project the Rust-side Conversation event into the local
/// `PendingContact` shape. Exported for tests so we can pin the
/// member-walk that picks the sender out of the welcome.
export function projectPendingContact(
  ev: ContactRequestEvent,
  myId: string | null,
  nowMs: number,
): PendingContact | null {
  // The welcome payload contains both the local user and the sender
  // as members. Pick the first member whose first device's
  // `agent_id_hex` isn't ours.
  let peer: string | null = null;
  for (const m of ev.members ?? []) {
    const dev = m.devices?.[0];
    const id = dev?.agent_id_hex;
    if (id && id !== myId) {
      peer = id;
      break;
    }
  }
  if (!peer) return null;
  return {
    groupIdHex: ev.group_id_hex,
    peerAgentId: peer,
    arrivedAtMs: nowMs,
  };
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
  const unsubContactReq = await listen<ContactRequestEvent>(
    "chat:contact-request",
    (ev) => {
      // Identity must be resolved before we project, otherwise the
      // "first non-self member" walk has no anchor and could pick the
      // local user as the peer. Safe to drop pre-identity events —
      // the backend persists the Conversation and will re-emit once
      // the panel reconnects.
      const me = store.myId();
      if (!me) return;
      const entry = projectPendingContact(ev.payload, me, Date.now());
      if (entry) store.addPendingContact(entry);
    },
  );
  return () => {
    unsubEvent();
    unsubReceipt();
    unsubPresence();
    unsubNearby();
    unsubDaemon();
    unsubContactReq();
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
