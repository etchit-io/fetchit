// Local-only chat state: conversation list, message transcripts,
// contact roster, presence map, my identity. DM transcripts persist
// to localStorage (the daemon does not retain them); everything else
// is rebuilt from the daemon on each open.

import type {
  AgentId,
  AgentIdentity,
  Contact,
  DirectMessage,
  Group,
  GroupMessage,
  OnlineAgent,
  PresenceTransition,
} from "./types";
import { loadDms, saveDms, type PersistedDm } from "./persistence";

/// A peer is considered grey if its last beacon is older than this.
/// x0xd's own eviction window is far longer (5+ minutes) and a healthy
/// peer's gossip beacon to main can lag several minutes despite the
/// QUIC link being fine. 90s was too tight in practice and would grey
/// out reachable peers; 5 minutes still catches crashed peers well
/// before the daemon's own eviction.
export const STALE_PRESENCE_MS = 300_000;

interface PresenceEntry {
  state: "online" | "offline";
  lastSeenMs: number;
}

/// One LAN-announced peer surfaced through the `chat:nearby` Tauri
/// event. Mirrors the desktop `NearbyPeer` Rust type.
export interface NearbyPeer {
  agentId: AgentId;
  ip: string;
  port: number;
  lastSeenMsAgo: number;
}

export type ConversationKey =
  | { kind: "dm"; peer: AgentId }
  | { kind: "group"; groupId: string };

export interface Conversation {
  key: ConversationKey;
  title: string;
  messages: ChatBubble[];
  unread: number;
  lastActivityMs: number;
}

/// Delivery status for outbound bubbles. Inbound bubbles leave this
/// unset (treated as delivered by renderers).
///
/// State machine:
///   sending   — message is in flight or queued for retry until the
///               recipient comes online. Includes the brief pre-ack
///               window AND the longer wait between relay ack and the
///               recipient's DeliveryReceipt.
///   delivered — recipient emitted a DeliveryReceipt and we decoded it.
///   failed    — transport reported error OR the 24h receipt-wait window
///               expired with no receipt.
export type BubbleStatus = "sending" | "delivered" | "failed";

/// Local-daemon health, surfaced by the backend's `chat:daemon-status`
/// Tauri event. The header pill paints green for `connected`, amber
/// for `reconnecting`, red for `down`. Driven by file-signature
/// changes on x0xd's `api.port` / `api-token` so the panel
/// self-heals after the daemon auto-upgrades or restarts.
export type DaemonStatus = "connected" | "reconnecting" | "down";

/// A first-contact welcome the user hasn't yet accepted. The
/// underlying `Conversation` is already persisted by the backend
/// (so we can decrypt subsequent messages from the same sender);
/// surfacing this entry to the UI is the only way the user can
/// confirm or refuse the contact. Wire shape mirrors a subset of
/// the Rust `Conversation` struct — we only project what the dialog
/// needs to render the request.
export interface PendingContact {
  /// 32-byte hex group identifier — opaque to the user, used by
  /// `chat_confirm_contact` to flip the trust state.
  groupIdHex: string;
  /// 64-hex agent id of the sender. Identifies them in the dialog
  /// and serves as the argument to `chat_remove_contact` on reject.
  peerAgentId: AgentId;
  /// Unix-ms when the welcome arrived. Pending requests sort newest
  /// first.
  arrivedAtMs: number;
}

export interface ChatBubble {
  id: string;
  /// Chat-layer logical message id assigned by the daemon. Populated
  /// once the send resolves so receipts (which echo this id) can flip
  /// the matching bubble to "delivered".
  messageId?: string;
  from: AgentId;
  body: string;
  timestampMs: number;
  mine: boolean;
  status?: BubbleStatus;
  failureReason?: string;
  retryAttempts?: number;
}


type Listener = () => void;

export class ChatStore {
  private myIdentity: AgentIdentity | null = null;
  private contacts = new Map<AgentId, Contact>();
  private presence = new Map<AgentId, PresenceEntry>();
  /// Authoritative relay-source presence. Wins over `presence` (which
  /// decays via STALE_PRESENCE_MS) because the relay only emits a
  /// PresenceUpdate on actual register / unregister — between events
  /// the last value remains true.
  private relayPresence = new Map<AgentId, boolean>();
  private conversations = new Map<string, Conversation>();
  private activeKey: string | null = null;
  private panelVisible = false;
  private listeners = new Set<Listener>();
  /// LAN-direct nearby peers — keyed by AgentId. Fed by the `chat:nearby`
  /// Tauri event when LAN delivery is enabled in settings. Empty
  /// otherwise. Sidebar renders this filtered against `contacts`.
  private nearbyPeers = new Map<AgentId, NearbyPeer>();
  /// State of the local x0xd daemon, surfaced by the
  /// `chat:daemon-status` Tauri event. Drives the header pill so the
  /// user can tell at a glance whether sends are expected to work
  /// right now. `null` means the watcher hasn't reported yet (early
  /// boot); UI should treat that as "connected" until proved otherwise.
  private daemonStatus: DaemonStatus | null = null;
  /// First-contact welcomes from previously-unknown senders, fed by
  /// the `chat:contact-request` Tauri event. Keyed by `group_id_hex`
  /// so a duplicate event for the same conversation overwrites
  /// (the registry only emits one Pending welcome per peer).
  /// The chat panel surfaces a "X pending contact requests" badge
  /// and the pending-contacts dialog reads from here.
  private pendingContacts = new Map<string, PendingContact>();

  subscribe(fn: Listener): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  private emit(): void {
    for (const fn of this.listeners) fn();
  }

  setIdentity(id: AgentIdentity): void {
    const changed = this.myIdentity?.agent_id !== id.agent_id;
    this.myIdentity = id;
    if (changed) this.hydrate();
    this.emit();
  }

  identity(): AgentIdentity | null {
    return this.myIdentity;
  }

  myId(): AgentId | null {
    return this.myIdentity?.agent_id ?? null;
  }

  loadContacts(list: Contact[]): void {
    this.contacts.clear();
    for (const c of list) this.contacts.set(c.agent_id, c);
    const me = this.myId();
    for (const c of list) {
      if (c.agent_id === me) continue;
      if (c.trust_level !== "known" && c.trust_level !== "trusted") continue;
      this.ensureDm(c.agent_id);
    }
    this.emit();
  }

  upsertContact(c: Contact): void {
    this.contacts.set(c.agent_id, c);
    this.emit();
  }

  removeContact(agentId: AgentId): void {
    this.contacts.delete(agentId);
    this.emit();
  }

  allContacts(): Contact[] {
    return [...this.contacts.values()].sort((a, b) =>
      contactSortKey(a).localeCompare(contactSortKey(b)),
    );
  }

  contact(id: AgentId): Contact | undefined {
    return this.contacts.get(id);
  }

  /// Record a first-contact TOFU welcome. Idempotent on `groupIdHex`
  /// — re-emitted events for the same conversation update the
  /// `arrivedAtMs` without spawning a duplicate badge entry.
  addPendingContact(entry: PendingContact): void {
    this.pendingContacts.set(entry.groupIdHex, entry);
    this.emit();
  }

  /// Drop a pending request once the user has accepted or rejected
  /// it. Safe to call on an absent key (no-op).
  removePendingContact(groupIdHex: string): void {
    if (this.pendingContacts.delete(groupIdHex)) {
      this.emit();
    }
  }

  /// Snapshot pending requests, newest first. Used by the chat
  /// panel header to render the badge count and by the pending
  /// dialog to render the list.
  allPendingContacts(): PendingContact[] {
    return [...this.pendingContacts.values()].sort(
      (a, b) => b.arrivedAtMs - a.arrivedAtMs,
    );
  }

  /// Replace the entire Nearby table with `peers`. Called on every
  /// `chat:nearby` event so the UI reflects fresh + dropped entries.
  setNearbyPeers(peers: NearbyPeer[]): void {
    this.nearbyPeers.clear();
    for (const p of peers) {
      this.nearbyPeers.set(p.agentId, p);
    }
    this.emit();
  }

  /// Update the local-daemon status, fed by the `chat:daemon-status`
  /// Tauri event. Only re-emits to subscribers when the value
  /// actually changes; otherwise the chat-bubble-pop fix's signature
  /// short-circuit would still treat each duplicate event as a tick.
  setDaemonStatus(status: DaemonStatus): void {
    if (this.daemonStatus === status) return;
    this.daemonStatus = status;
    this.emit();
  }

  /// Current local-daemon status, or `null` if the watcher hasn't
  /// reported yet (early-boot). The header pill should paint green
  /// while `null` so the UI isn't yellow-screaming during normal
  /// startup.
  getDaemonStatus(): DaemonStatus | null {
    return this.daemonStatus;
  }

  /// Nearby peers minus any already in the contact store. The Nearby
  /// sidebar section renders this; AgentIds already known to the user
  /// don't need a re-add affordance.
  nearbyPeersUnknown(): NearbyPeer[] {
    const me = this.myId();
    return [...this.nearbyPeers.values()]
      .filter((p) => p.agentId !== me)
      .filter((p) => !this.contacts.has(p.agentId))
      .sort((a, b) => a.agentId.localeCompare(b.agentId));
  }

  loadPresence(agents: OnlineAgent[]): void {
    this.presence.clear();
    const now = Date.now();
    for (const a of agents) {
      const lastSeenMs = typeof a.last_seen === "number"
        ? a.last_seen * 1000
        : now;
      this.presence.set(a.agent_id, { state: "online", lastSeenMs });
    }
    this.emit();
  }

  applyPresenceTransition(t: PresenceTransition): void {
    if (t.event === "online") {
      this.presence.set(t.agent_id, {
        state: "online",
        lastSeenMs: Date.now(),
      });
    } else if (t.event === "offline") {
      const existing = this.presence.get(t.agent_id);
      this.presence.set(t.agent_id, {
        state: "offline",
        lastSeenMs: existing?.lastSeenMs ?? 0,
      });
    }
    this.emit();
  }

  isOnline(id: AgentId): boolean {
    const relay = this.relayPresence.get(id);
    if (relay !== undefined) return relay;
    const entry = this.presence.get(id);
    if (!entry || entry.state !== "online") return false;
    return Date.now() - entry.lastSeenMs < STALE_PRESENCE_MS;
  }

  /// Authoritative relay-source presence flip. The relay only emits a
  /// PresenceUpdate on actual register / unregister, so the last value
  /// stays valid until the next transition — no staleness decay.
  setRelayPresence(id: AgentId, online: boolean): void {
    this.relayPresence.set(id, online);
    this.emit();
  }

  /// Force a re-render so views re-evaluate isOnline(); called by a
  /// periodic panel-level ticker to age out stale beacons.
  tickPresence(): void {
    this.emit();
  }

  /// Merge a fresh `/presence/online` snapshot into the live map.
  /// Unlike loadPresence, this does not reset — it only promotes peers
  /// to online when the snapshot's last_seen is newer than what we
  /// already have. Used by the panel ticker as a safety net for SSE
  /// transitions that get dropped during a reconnect window.
  mergePresenceSnapshot(agents: OnlineAgent[]): void {
    const now = Date.now();
    for (const a of agents) {
      const lastSeenMs = typeof a.last_seen === "number"
        ? a.last_seen * 1000
        : now;
      const existing = this.presence.get(a.agent_id);
      if (!existing || existing.lastSeenMs < lastSeenMs) {
        this.presence.set(a.agent_id, { state: "online", lastSeenMs });
      }
    }
    this.emit();
  }

  loadGroups(groups: Group[]): void {
    const present = new Set<string>();
    for (const g of groups) {
      const k = `g:${g.group_id}`;
      present.add(k);
      if (!this.conversations.has(k)) {
        this.conversations.set(k, {
          key: { kind: "group", groupId: g.group_id },
          title: g.name ?? g.group_id.slice(0, 8),
          messages: [],
          unread: 0,
          lastActivityMs: 0,
        });
      } else {
        const existing = this.conversations.get(k)!;
        existing.title = g.name ?? existing.title;
      }
    }
    // Drop group conversations the daemon no longer reports — left
    // or deleted groups would otherwise linger in the sidebar.
    for (const [key, conv] of this.conversations) {
      if (conv.key.kind !== "group") continue;
      if (present.has(key)) continue;
      this.conversations.delete(key);
      if (this.activeKey === key) this.activeKey = null;
    }
    this.emit();
  }

  recordGroupHistory(groupId: string, messages: GroupMessage[]): void {
    const key = `g:${groupId}`;
    const conv = this.ensureGroup(groupId);
    const next = messages.map((m) => ({
      id: m.message_id,
      from: m.from,
      body: m.body,
      timestampMs: m.timestamp_ms,
      mine: m.from === this.myId(),
    }));
    // Skip the emit when the poll returned the same set we already
    // have — re-rendering the stream every 4s tears down any in-flight
    // bubble state (autonomi:// preview cards, scroll position, focus).
    if (sameMessages(conv.messages, next)) return;
    conv.messages = next;
    conv.lastActivityMs =
      messages.length > 0 ? messages[messages.length - 1].timestamp_ms : 0;
    this.conversations.set(key, conv);
    this.emit();
  }

  recordDirectMessage(dm: DirectMessage): void {
    const me = this.myId();
    const peer = dm.from === me ? (dm.to ?? "") : dm.from;
    if (!peer) return;
    const conv = this.ensureDm(peer);
    const ts = dm.timestamp_ms ?? Date.now();
    const bubble: ChatBubble = {
      id: dm.message_id ?? `local-${ts}-${Math.random().toString(36).slice(2, 6)}`,
      from: dm.from,
      body: dm.body,
      timestampMs: ts,
      mine: dm.from === me,
    };
    if (bubble.id && conv.messages.some((m) => m.id === bubble.id)) {
      return;
    }
    conv.messages.push(bubble);
    conv.lastActivityMs = ts;
    // "Seen" requires both: panel visible AND this conv is the active
    // one. Otherwise (panel closed, OR a different conv showing) the
    // message bumps unread so the header badge + ping fire.
    const seen
      = this.panelVisible && this.activeKey === convKey(conv.key);
    if (!bubble.mine && !seen) {
      conv.unread += 1;
    }
    this.persistDms();
    this.emit();
  }

  conversationsSorted(): Conversation[] {
    return [...this.conversations.values()].sort(
      (a, b) => b.lastActivityMs - a.lastActivityMs,
    );
  }

  /// Total unread count across every conversation. Used by the
  /// header-bar chat button badge so the user sees pending traffic
  /// even when the chat panel itself is closed.
  unreadCount(): number {
    let total = 0;
    for (const conv of this.conversations.values()) total += conv.unread;
    return total;
  }

  ensureDm(peer: AgentId): Conversation {
    const key = `dm:${peer}`;
    let conv = this.conversations.get(key);
    if (!conv) {
      const title = this.contact(peer)?.label
        ?? this.contact(peer)?.display_name
        ?? `${peer.slice(0, 8)}…`;
      conv = {
        key: { kind: "dm", peer },
        title,
        messages: [],
        unread: 0,
        lastActivityMs: 0,
      };
      this.conversations.set(key, conv);
    }
    return conv;
  }

  ensureGroup(groupId: string): Conversation {
    const key = `g:${groupId}`;
    let conv = this.conversations.get(key);
    if (!conv) {
      conv = {
        key: { kind: "group", groupId },
        title: groupId.slice(0, 8),
        messages: [],
        unread: 0,
        lastActivityMs: 0,
      };
      this.conversations.set(key, conv);
    }
    return conv;
  }

  setActive(key: ConversationKey | null): void {
    if (!key) {
      this.activeKey = null;
    } else {
      this.activeKey = convKey(key);
      // Only clear unread when the panel is actually open — otherwise
      // a panel-closed setActive (e.g. restored state on reload)
      // would silently consume the badge without the user seeing
      // the messages.
      if (this.panelVisible) {
        const conv = this.conversations.get(this.activeKey);
        if (conv && conv.unread !== 0) {
          conv.unread = 0;
          this.persistDms();
        }
      }
    }
    this.emit();
  }

  /// The panel reports its visibility so the store can decide what
  /// counts as "seen" for unread tracking and unread-reset logic.
  setPanelVisible(visible: boolean): void {
    if (this.panelVisible === visible) return;
    this.panelVisible = visible;
    // Becoming visible while a conv is already active = the user just
    // unhid the chat with their last conversation in front of them →
    // mark it read.
    if (visible && this.activeKey) {
      const conv = this.conversations.get(this.activeKey);
      if (conv && conv.unread !== 0) {
        conv.unread = 0;
        this.persistDms();
      }
    }
    this.emit();
  }

  active(): Conversation | null {
    if (!this.activeKey) return null;
    return this.conversations.get(this.activeKey) ?? null;
  }

  /// Append an outbound bubble in "sending" state and return its id so
  /// the caller can flip it through sent → delivered/failed as the send
  /// resolves and the recipient's receipt arrives.
  enqueueOutbound(peer: AgentId, body: string): string {
    const me = this.myId() ?? "";
    const ts = Date.now();
    const id = `local-${ts}-${Math.random().toString(36).slice(2, 8)}`;
    const conv = this.ensureDm(peer);
    conv.messages.push({
      id,
      from: me,
      body,
      timestampMs: ts,
      mine: true,
      status: "sending",
      retryAttempts: 0,
    });
    conv.lastActivityMs = ts;
    this.persistDms();
    this.emit();
    return id;
  }

  /// Bind the daemon-assigned `messageId` so an inbound DeliveryReceipt
  /// can later promote the bubble to "delivered". Does NOT advance the
  /// visible status — the bubble stays at "sending" until either a
  /// receipt arrives or the 24h timeout expires.
  ///
  /// A successful retry of a previously-failed bubble re-enters
  /// "sending" so the user sees the in-flight clock again.
  markSent(peer: AgentId, bubbleId: string, messageId: string | null): void {
    const conv = this.conversations.get(`dm:${peer}`);
    if (!conv) return;
    const b = conv.messages.find((m) => m.id === bubbleId);
    if (!b) return;
    if (b.status === "failed") b.status = "sending";
    b.failureReason = undefined;
    if (messageId !== null) b.messageId = messageId;
    this.persistDms();
    this.emit();
  }

  /// Locate the bubble whose `messageId` matches `messageId` and flip
  /// it to "delivered". Called when a `chat:receipt` event arrives from
  /// the daemon.
  markDelivered(peer: AgentId, messageId: string): void {
    const conv = this.conversations.get(`dm:${peer}`);
    if (!conv) return;
    const b = conv.messages.find((m) => m.messageId === messageId);
    if (!b) return;
    b.status = "delivered";
    b.failureReason = undefined;
    this.persistDms();
    this.emit();
  }

  /// Bump a peer's last-seen to now and mark them online. Called when
  /// we have direct evidence of reachability — a successful outbound
  /// send, or a connect probe when entering a DM — so the dot stays
  /// green even when the daemon's gossip beacon view is stale.
  touchPresence(peer: AgentId): void {
    this.presence.set(peer, { state: "online", lastSeenMs: Date.now() });
    this.emit();
  }

  markFailed(peer: AgentId, bubbleId: string, reason: string): void {
    const conv = this.conversations.get(`dm:${peer}`);
    if (!conv) return;
    const b = conv.messages.find((m) => m.id === bubbleId);
    if (!b) return;
    b.status = "failed";
    b.failureReason = reason;
    b.retryAttempts = (b.retryAttempts ?? 0) + 1;
    this.persistDms();
    this.emit();
  }

  markPending(peer: AgentId, bubbleId: string): void {
    const conv = this.conversations.get(`dm:${peer}`);
    if (!conv) return;
    const b = conv.messages.find((m) => m.id === bubbleId);
    if (!b) return;
    b.status = "sending";
    this.emit();
  }

  /// Reset retry counters on every failed bubble so the driver gives
  /// them another full budget. Used by the manual "Retry" affordance
  /// in the outbox banner.
  resetFailedRetryCounters(): number {
    let touched = 0;
    for (const conv of this.conversations.values()) {
      if (conv.key.kind !== "dm") continue;
      for (const m of conv.messages) {
        if (m.status === "failed" && (m.retryAttempts ?? 0) > 0) {
          m.retryAttempts = 0;
          touched += 1;
        }
      }
    }
    if (touched > 0) {
      this.persistDms();
      this.emit();
    }
    return touched;
  }

  /// Every bubble that hasn't been confirmed delivered, across all DM
  /// conversations. Used by the outbox driver to find retry work and
  /// by the UI to render the "waiting to deliver" banner.
  pendingOutbound(): Array<{ peer: AgentId; bubble: ChatBubble }> {
    const out: Array<{ peer: AgentId; bubble: ChatBubble }> = [];
    for (const conv of this.conversations.values()) {
      if (conv.key.kind !== "dm") continue;
      for (const m of conv.messages) {
        if (!m.mine) continue;
        if (m.status === "sending" || m.status === "failed") {
          out.push({ peer: conv.key.peer, bubble: m });
        }
      }
    }
    return out;
  }

  /// Drop a DM transcript both in-memory and from storage. Used when a
  /// contact is blocked or removed.
  clearDmTranscript(peer: AgentId): void {
    const key = `dm:${peer}`;
    if (this.conversations.delete(key)) {
      if (this.activeKey === key) this.activeKey = null;
      this.persistDms();
      this.emit();
    }
  }

  private hydrate(): void {
    const me = this.myId();
    if (!me) return;
    const persisted = loadDms(me);
    for (const [peer, dm] of persisted) {
      const conv = this.ensureDm(peer);
      conv.messages = dm.messages;
      conv.unread = dm.unread;
      conv.lastActivityMs = dm.lastActivityMs;
    }
  }

  private persistDms(): void {
    const me = this.myId();
    if (!me) return;
    const out = new Map<AgentId, PersistedDm>();
    for (const conv of this.conversations.values()) {
      if (conv.key.kind !== "dm") continue;
      out.set(conv.key.peer, {
        messages: conv.messages,
        unread: conv.unread,
        lastActivityMs: conv.lastActivityMs,
      });
    }
    saveDms(me, out);
  }
}

export function convKey(k: ConversationKey): string {
  return k.kind === "dm" ? `dm:${k.peer}` : `g:${k.groupId}`;
}

function contactSortKey(c: Contact): string {
  return (c.label ?? c.display_name ?? c.agent_id).toLowerCase();
}

function sameMessages(a: ChatBubble[], b: ChatBubble[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i].id !== b[i].id) return false;
  }
  return true;
}
