// Retry driver for queued outbound DMs. Subscribes to the store and,
// on every emit, tries to redeliver any pending/failed bubble whose
// peer is currently online. Caps automatic retries at MAX_AUTO_RETRIES;
// past that the user has to manually re-send.

import type { ChatStore } from "./state";
import { MAX_AUTO_RETRIES } from "./state";
import type { AgentId } from "./types";

export interface OutboxDriverDeps {
  sendDm: (peer: AgentId, body: string) => Promise<string | null>;
}

export function startOutboxDriver(
  store: ChatStore,
  deps: OutboxDriverDeps,
): () => void {
  const inflight = new Set<string>();

  const tick = (): void => {
    for (const { peer, bubble } of store.pendingOutbound()) {
      // Initial-send bubbles (status="pending") are handled by their
      // own in-flight promise in conversation.ts; the driver only
      // retries bubbles the daemon has already rejected.
      if (bubble.status !== "failed") continue;
      if (!store.isOnline(peer)) continue;
      if (inflight.has(bubble.id)) continue;
      if ((bubble.retryAttempts ?? 0) >= MAX_AUTO_RETRIES) continue;
      inflight.add(bubble.id);
      void deps
        .sendDm(peer, bubble.body)
        .then(() => store.markDelivered(peer, bubble.id))
        .catch((e: unknown) =>
          store.markFailed(peer, bubble.id, (e as Error).message),
        )
        .finally(() => inflight.delete(bubble.id));
    }
  };

  const unsub = store.subscribe(tick);
  // Run once immediately to flush anything pending at startup (e.g.
  // bubbles restored from localStorage after fetch>it restarted).
  tick();
  return unsub;
}
