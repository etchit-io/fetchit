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
  PresenceTransition,
} from "./types";
import { loadDms, saveDms, type PersistedDm } from "./persistence";

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

export interface ChatBubble {
  id: string;
  from: AgentId;
  body: string;
  timestampMs: number;
  mine: boolean;
}

type Listener = () => void;

export class ChatStore {
  private myIdentity: AgentIdentity | null = null;
  private contacts = new Map<AgentId, Contact>();
  private presence = new Map<AgentId, "online" | "offline">();
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

  loadPresence(online: AgentId[]): void {
    this.presence.clear();
    for (const id of online) this.presence.set(id, "online");
    this.emit();
  }

  applyPresenceTransition(t: PresenceTransition): void {
    if (t.event === "online") this.presence.set(t.agent_id, "online");
    else if (t.event === "offline") this.presence.set(t.agent_id, "offline");
    this.emit();
  }

  isOnline(id: AgentId): boolean {
    return this.presence.get(id) === "online";
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
