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

/// Wire-shape of the daemon's `chat:relay-status` Tauri event.
/// Currently emits only the terminal `permanently_disconnected`
/// transition — transient flaky-network noise stays in-process.
interface RelayStatusEvent {
  kind: string;
  reason?: string;
  attempts?: number;
}

/// Wire-shape of the daemon's `chat:warn` Tauri event. The `kind`
/// discriminates the four crypto-layer failure paths the chat
/// pipeline can hit; the dialog turns each into a grandma-readable
/// banner via [`warnEventToCopy`].
interface WarnEvent {
  kind: string;
  group_id?: string;
  epoch?: number;
  sender?: string;
}

/// Translate a `chat:warn` payload into user-visible copy. Kept
/// exported so tests can pin the mapping when the Rust side grows
/// new warn variants.
export function warnEventToCopy(ev: WarnEvent): string {
  switch (ev.kind) {
    case "stale_epoch":
      return "A group has new members — refreshing keys…";
    case "kem_decap_failed":
      return "Couldn't unlock a message — the sender may need to rekey.";
    case "aead_open_failed":
      return "A message failed authentication and was dropped.";
    case "Dropped":
      return "A message was dropped.";
    default:
      // Surface the raw kind in dev builds so unknown warns surface
      // at all; production users still get a generic notice.
      return `Something went wrong: ${ev.kind}`;
  }
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

/// Wire-shape of the daemon's `chat:denylist-updated` Tauri event —
/// mirrors `fetchit_trust_client::BlockEvent`. `kind` is the
/// snake_case `EntryKind` discriminant; `added` / `removed` are the
/// canonical-form values that entered / left the denylist for that
/// kind. The G2 contacts indicator consumes only the `agent_id` kind.
interface DenylistUpdateEvent {
  kind: string;
  added: string[];
  removed: string[];
}

/// M3 G2: apply a `chat:denylist-updated` event to the store's blocked
/// set. Only the `agent_id` kind drives the contacts indicator —
/// `xor_name` / `relay_url` / `actor_url` transitions are consumed by
/// other surfaces (reader Blocked render, relay-denylisted banner,
/// fediverse gate) and are ignored here. Exported for direct testing
/// without a Tauri `listen` mock.
export function applyDenylistUpdateEvent(
  store: ChatStore,
  ev: DenylistUpdateEvent,
): void {
  if (ev.kind !== "agent_id") return;
  store.applyDenylistUpdate(ev.added ?? [], ev.removed ?? []);
}

/// M3 G1: build a stateful handler for the `chat:relay-denylisted`
/// event (payload = the user's primary relay URL that just landed on
/// the community denylist). Dedupes by URL for the session so a
/// broadcast `Lagged`-gap recovery or a duplicate `added` entry can't
/// stack identical banners (Bob's G1 idempotency note). Exported so the
/// dedup contract is unit-testable without a Tauri `listen` mock.
///
/// The user is NOT disconnected — slot 0 (the primary) is deliberately
/// kept by `MultiHomeTransport` on a denylist hit (the D6 "Settings
/// concern" contract), so the copy informs + suggests a switch rather
/// than implying the link is dead.
export function makeRelayDenylistedHandler(
  store: ChatStore,
): (url: string) => void {
  const surfaced = new Set<string>();
  return (url: string) => {
    if (surfaced.has(url)) return;
    surfaced.add(url);
    store.pushNotice(
      "warn",
      `The relay you connect through (${url}) was added to the community `
        + "safety denylist. You're still connected, but consider switching "
        + "relays in Settings → Network.",
    );
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
  const unsubWarn = await listen<WarnEvent>("chat:warn", (ev) => {
    console.warn("[chat:warn]", ev.payload);
    store.pushNotice("warn", warnEventToCopy(ev.payload));
  });
  const unsubRelayStatus = await listen<RelayStatusEvent>(
    "chat:relay-status",
    (ev) => {
      console.warn("[chat:relay-status]", ev.payload);
      if (ev.payload.kind === "permanently_disconnected") {
        store.pushNotice(
          "warn",
          "Lost connection to the chat relay. Close and reopen Chat to reconnect.",
        );
      }
    },
  );
  const onRelayDenylisted = makeRelayDenylistedHandler(store);
  const unsubRelayDenylisted = await listen<string>(
    "chat:relay-denylisted",
    (ev) => {
      console.warn("[chat:relay-denylisted]", ev.payload);
      onRelayDenylisted(ev.payload);
    },
  );
  const unsubDenylistUpdate = await listen<DenylistUpdateEvent>(
    "chat:denylist-updated",
    (ev) => {
      applyDenylistUpdateEvent(store, ev.payload);
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
    unsubWarn();
    unsubRelayStatus();
    unsubRelayDenylisted();
    unsubDenylistUpdate();
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
