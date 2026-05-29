// Retry driver for queued outbound DMs. Mirrors what a person would
// do by hand: when a peer transitions from offline to online, try
// each of their failed bubbles once. If the retry fails the bubble
// stays failed until the next transition (or a manual Retry click).
// No artificial cap — the trigger is bounded by real presence edges.

import type { ChatStore } from "./state";
import type { AgentId } from "./types";

export interface OutboxDriverDeps {
  sendDm: (peer: AgentId, body: string) => Promise<string | null>;
  /// Warm up the QUIC link before retrying. x0xd's `/direct/send`
  /// times out at 12s when the link is cold even though the peer is
  /// reachable via gossip; an explicit `/agents/connect` establishes
  /// the direct path so the next send returns in milliseconds.
  connect: (peer: AgentId) => Promise<void>;
}

export interface OutboxDriver {
  /// Stop subscribing to the store (cancels future automatic retries).
  stop(): void;
  /// Force a retry sweep across all online peers with failed bubbles,
  /// regardless of presence-edge state. Used by the "Retry" button.
  flushAll(): void;
}

export function startOutboxDriver(
  store: ChatStore,
  deps: OutboxDriverDeps,
): OutboxDriver {
  const inflight = new Set<string>();
  // Tracks each peer's most recent online/offline state so we can
  // detect offline→online edges and trigger one retry sweep per edge.
  const lastOnline = new Map<AgentId, boolean>();

  const flushPeer = (peer: AgentId): void => {
    for (const { peer: p, bubble } of store.pendingOutbound()) {
      if (p !== peer) continue;
      if (bubble.status !== "failed") continue;
      if (inflight.has(bubble.id)) continue;
      inflight.add(bubble.id);
      void (async () => {
        try {
          await deps.connect(peer).catch(() => {});
          const messageId = await deps.sendDm(peer, bubble.body);
          store.markSent(peer, bubble.id, messageId);
        } catch (e) {
          store.markFailed(peer, bubble.id, (e as Error).message);
        } finally {
          inflight.delete(bubble.id);
        }
      })();
    }
  };

  const tick = (): void => {
    const seen = new Set<AgentId>();
    for (const { peer, bubble } of store.pendingOutbound()) {
      if (bubble.status !== "failed") continue;
      if (seen.has(peer)) continue;
      seen.add(peer);
      const online = store.isOnline(peer);
      const wasOnline = lastOnline.get(peer) === true;
      lastOnline.set(peer, online);
      // Two firing conditions: the natural offline→online edge that
      // matches "wait until peer is back, then send"; and the
      // initial-load case where we already see them online and have
      // never observed a state (likely after fetch>it restart).
      const transition = online && !wasOnline;
      const initialPickup = online && !lastOnline.has(peer);
      if (transition || initialPickup) {
        flushPeer(peer);
      }
    }
    // Reflect the latest snapshot for peers without pending bubbles
    // too, so a future failed bubble triggers correctly on the next
    // transition rather than mistaking initial state for an edge.
    for (const conv of store.conversationsSorted()) {
      if (conv.key.kind !== "dm") continue;
      const peer = conv.key.peer;
      if (seen.has(peer)) continue;
      lastOnline.set(peer, store.isOnline(peer));
    }
  };

  const flushAll = (): void => {
    const seen = new Set<AgentId>();
    for (const { peer } of store.pendingOutbound()) {
      if (seen.has(peer)) continue;
      seen.add(peer);
      if (store.isOnline(peer)) flushPeer(peer);
    }
  };

  const unsub = store.subscribe(tick);
  tick();
  return { stop: unsub, flushAll };
}
