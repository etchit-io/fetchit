// Wire the daemon's SSE event stream — already proxied through Tauri
// as `chat:event` — into the local store.

import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { maybeNotifyInboundDm } from "./notify";
import type { ChatStore, DaemonStatus, NearbyPeer, PendingContact } from "./state";
import type { ChatEvent, GroupMessage, OutboxBubbleDto } from "./types";

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

/// Wire-shape of the daemon's `chat:relay-status` Tauri event. One
/// per supervisor ConnState transition: `connecting`, `connected`,
/// `reconnecting`, and the terminal `permanently_disconnected`.
export interface RelayStatusEvent {
  kind: string;
  reason?: string;
  attempts?: number;
}

/// Map one `chat:relay-status` payload onto the store: the header
/// pill state for every transition, plus the lost-connection notice
/// on the terminal one. Unknown kinds are dropped so a newer backend
/// can grow the vocabulary without breaking an older frontend.
export function applyRelayStatusEvent(
  store: ChatStore,
  payload: RelayStatusEvent,
): void {
  switch (payload.kind) {
    case "connecting":
    case "connected":
    case "reconnecting":
      store.setRelayStatus(payload.kind);
      break;
    case "permanently_disconnected":
      store.setRelayStatus("down");
      store.pushNotice(
        "warn",
        "Lost connection to the chat relay. Close and reopen Chat to reconnect.",
      );
      break;
  }
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
  /// Raw engine error string, carried by `private_group_decrypt_failed`.
  /// Logged but not shown to the user.
  error?: string;
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
    case "private_group_decrypt_failed":
      return "Couldn't decrypt a group message; the group key may be out of date.";
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

/// Wire-shape of the backend's `chat:relay-failover` Tauri event (T9).
/// `kind` is `"migrated"` (home relay was swapped to a live fallback) or
/// `"failed"` (no fallback reachable). The backend persists the new relay
/// URL on `migrated`, so the Settings → Network region picker re-reads the
/// live primary the next time it mounts (`refreshRelay`); this handler only
/// surfaces the transient banner.
interface RelayFailoverEvent {
  kind: "migrated" | "failed";
  from?: string;
  to?: string;
  dead?: string;
}

/// T9: build a handler for the `chat:relay-failover` event. A `migrated`
/// event paints an info notice naming the new relay; a `failed` event paints
/// a warning. Exported so the copy + severity mapping is unit-testable
/// without a Tauri `listen` mock.
export function makeRelayFailoverHandler(
  store: ChatStore,
): (ev: RelayFailoverEvent) => void {
  return (ev: RelayFailoverEvent) => {
    if (ev.kind === "migrated" && ev.to) {
      store.pushNotice(
        "info",
        `Relay connection moved to ${ev.to}. Your contacts update automatically.`,
      );
    } else if (ev.kind === "failed") {
      store.pushNotice(
        "warn",
        "Lost your home relay and couldn't reach a backup. "
          + "Check Settings → Network to pick another region.",
      );
    }
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
      applyRelayStatusEvent(store, ev.payload);
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
  const onRelayFailover = makeRelayFailoverHandler(store);
  const unsubRelayFailover = await listen<RelayFailoverEvent>(
    "chat:relay-failover",
    (ev) => {
      console.warn("[chat:relay-failover]", ev.payload);
      onRelayFailover(ev.payload);
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
  // Live inbound private-group message, decrypted backend-side and
  // emitted one-per-envelope. The store dedups by message_id so a
  // relay-pump reconnect that re-delivers the same envelope yields one
  // bubble. Distinct from `chat:event` (a dedicated event, not a
  // ChatEvent variant), so it is wired here, not in applyChatEvent.
  const unsubGroupMsg = await listen<GroupMessage>(
    "chat:group-message",
    (ev) => {
      store.appendGroupMessage(ev.payload);
    },
  );
  // Engine outbox projection: each `chat:outbox` is an upsert of one
  // outbound bubble (the engine owns send/retry/delivery). `resync`
  // carries a fresh snapshot after a broadcast lag.
  const unsubOutbox = await listen<OutboxBubbleDto>("chat:outbox", (ev) => {
    store.applyOutboxEvent(ev.payload);
  });
  const unsubOutboxResync = await listen<OutboxBubbleDto[]>(
    "chat:outbox-resync",
    (ev) => {
      // A lag dropped live events, so the FIFO of staged reply/attachment
      // metadata can no longer be trusted to align: clear it and re-apply
      // the authoritative snapshot (persisted bubbles keep their metadata).
      store.clearOutboundMeta();
      for (const bubble of ev.payload ?? []) store.applyOutboxEvent(bubble);
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
    unsubRelayFailover();
    unsubDenylistUpdate();
    unsubContactReq();
    unsubGroupMsg();
    unsubOutbox();
    unsubOutboxResync();
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
