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
export type BubbleStatus = "pending" | "delivered" | "failed";

export interface ChatBubble {
  id: string;
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
  private conversations = new Map<string, Conversation>();
  private activeKey: string | null = null;
  private listeners = new Set<Listener>();

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
    const entry = this.presence.get(id);
    if (!entry || entry.state !== "online") return false;
    return Date.now() - entry.lastSeenMs < STALE_PRESENCE_MS;
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
    for (const g of groups) {
      const k = `g:${g.group_id}`;
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
    this.emit();
  }

  recordGroupHistory(groupId: string, messages: GroupMessage[]): void {
    const key = `g:${groupId}`;
    const conv = this.ensureGroup(groupId);
    conv.messages = messages.map((m) => ({
      id: m.message_id,
      from: m.from,
      body: m.body,
      timestampMs: m.timestamp_ms,
      mine: m.from === this.myId(),
    }));
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
    if (!bubble.mine && this.activeKey !== convKey(conv.key)) {
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

  /// Append an outbound bubble in "pending" state and return its id so
  /// the caller can flip it to delivered/failed once the send resolves.
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
      status: "pending",
      retryAttempts: 0,
    });
    conv.lastActivityMs = ts;
    this.persistDms();
    this.emit();
    return id;
  }

  markDelivered(peer: AgentId, bubbleId: string): void {
    const conv = this.conversations.get(`dm:${peer}`);
    if (!conv) return;
    const b = conv.messages.find((m) => m.id === bubbleId);
    if (!b) return;
    b.status = "delivered";
    b.failureReason = undefined;
    // A successful send is proof the peer is reachable right now, so
    // refresh the staleness clock even if their gossip beacon is lagging.
    this.touchPresence(peer);
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
    b.status = "pending";
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
        if (m.status === "pending" || m.status === "failed") {
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
