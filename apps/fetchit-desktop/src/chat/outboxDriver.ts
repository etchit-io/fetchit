// Retry driver for queued outbound DMs.
//
// The relay's transit buffer is intentionally short (15 min). The client
// carries the longer retention: every offline→online edge for a peer
// triggers a fresh send for any of their bubbles that are still in
// flight or failed. A periodic sweep flips bubbles that have been
// in flight for more than `SEND_TIMEOUT_MS` to "failed" so the user
// gets an honest ⚠ instead of an indefinite ⏳.

import type { ChatBubble, ChatStore } from "./state";
import type { AgentId } from "./types";

/// How long a bubble may sit in "sending" before the sweeper flips it
/// to "failed". The user can still manually retry afterwards.
const SEND_TIMEOUT_MS = 24 * 60 * 60 * 1000;

/// When this module loaded. A bubble that is still "sending" without a
/// messageId but predates the JS session cannot have a live in-flight
/// promise (the world that owned it is gone), so the boot sweep may
/// safely flip it to "failed" without double-send risk. Module-level on
/// purpose: panel remounts restart the driver but do not reload the
/// module, so bubbles from the current session are never misclassified.
const SESSION_START_MS = Date.now();

/// How often the timeout sweeper runs. One minute is fine — the
/// timeout granularity is hours.
const SWEEP_INTERVAL_MS = 60_000;

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
  /// Force a retry sweep across all online peers, regardless of
  /// presence-edge state. Used by the "Retry" button.
  flushAll(): void;
}

/// A bubble is eligible for retry when it's either:
/// - "failed": the previous attempt errored out, the user wants another try; or
/// - "sending" *and* the daemon already assigned a `messageId` (= the
///   initial relay ACK landed). Without the messageId the original
///   send is still in flight, and re-firing would double-send.
function isRetryable(bubble: ChatBubble): boolean {
  if (bubble.status === "failed") return true;
  if (bubble.status === "sending" && bubble.messageId !== undefined) return true;
  return false;
}

export function startOutboxDriver(
  store: ChatStore,
  deps: OutboxDriverDeps,
  sessionStartMs: number = SESSION_START_MS,
): OutboxDriver {
  const inflight = new Set<string>();

  // Boot sweep: a "sending" bubble with no messageId is excluded from
  // every retry path (isRetryable) to avoid double-sends — but one that
  // predates this session is provably orphaned (its in-flight promise
  // died with the previous app run). Flip it to an honest "failed" so
  // the ⚠ shows and the normal retry machinery can reach it.
  for (const { peer, bubble } of store.pendingOutbound()) {
    if (bubble.status !== "sending") continue;
    if (bubble.messageId !== undefined) continue;
    if (bubble.timestampMs >= sessionStartMs) continue;
    store.markFailed(peer, bubble.id, "send interrupted by app restart");
  }
  // Tracks each peer's most recent online/offline state so we can
  // detect offline→online edges and trigger one retry sweep per edge.
  const lastOnline = new Map<AgentId, boolean>();

  const flushPeer = (peer: AgentId): void => {
    for (const { peer: p, bubble } of store.pendingOutbound()) {
      if (p !== peer) continue;
      if (!isRetryable(bubble)) continue;
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

  const sweepTimeouts = (): void => {
    const now = Date.now();
    for (const { peer, bubble } of store.pendingOutbound()) {
      if (bubble.status !== "sending") continue;
      if (now - bubble.timestampMs < SEND_TIMEOUT_MS) continue;
      store.markFailed(peer, bubble.id, "delivery timed out after 24h");
    }
  };

  const tick = (): void => {
    const seen = new Set<AgentId>();
    for (const { peer, bubble } of store.pendingOutbound()) {
      if (!isRetryable(bubble)) continue;
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
    // too, so a future eligible bubble triggers correctly on the next
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
    for (const { peer, bubble } of store.pendingOutbound()) {
      if (!isRetryable(bubble)) continue;
      if (seen.has(peer)) continue;
      seen.add(peer);
      if (store.isOnline(peer)) flushPeer(peer);
    }
  };

  const unsub = store.subscribe(tick);
  const sweepTimer = setInterval(sweepTimeouts, SWEEP_INTERVAL_MS);
  tick();
  return {
    stop: () => {
      unsub();
      clearInterval(sweepTimer);
    },
    flushAll,
  };
}
