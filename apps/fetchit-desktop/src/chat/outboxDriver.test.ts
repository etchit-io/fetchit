import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ChatStore } from "./state";
import { startOutboxDriver, type OutboxDriver } from "./outboxDriver";

const ME = "a".repeat(64);
const PEER = "b".repeat(64);

let store: ChatStore;
let sendDm: ReturnType<typeof vi.fn>;
let connect: ReturnType<typeof vi.fn>;
let driver: OutboxDriver | null;

beforeEach(() => {
  localStorage.clear();
  store = new ChatStore();
  store.setIdentity({ agent_id: ME, machine_id: "m" });
  sendDm = vi.fn();
  connect = vi.fn().mockResolvedValue(undefined);
  driver = null;
});

afterEach(() => {
  driver?.stop();
});

async function flushPromises(): Promise<void> {
  for (let i = 0; i < 8; i += 1) {
    await Promise.resolve();
  }
}

describe("outboxDriver — boot orphan sweep", () => {
  it("fails a pre-session sending bubble with no messageId", async () => {
    const id = store.enqueueOutbound(PEER, "orphan from last run");
    // Classify everything existing as pre-session by starting the
    // driver with a session boundary in the future.
    driver = startOutboxDriver(store, { sendDm, connect }, Date.now() + 60_000);
    const b = store.conversationsSorted()[0].messages.find((m) => m.id === id);
    expect(b?.status).toBe("failed");
    expect(b?.failureReason).toBe("send interrupted by app restart");
    // Now retryable through the normal machinery.
    sendDm.mockResolvedValue("server-id-9");
    store.applyPresenceTransition({ agent_id: PEER, event: "online" });
    await flushPromises();
    expect(sendDm).toHaveBeenCalledWith(PEER, "orphan from last run");
  });

  it("leaves current-session in-flight sends untouched", () => {
    const id = store.enqueueOutbound(PEER, "genuinely in flight");
    driver = startOutboxDriver(store, { sendDm, connect });
    const b = store.conversationsSorted()[0].messages.find((m) => m.id === id);
    // Enqueued after module load — its promise may be live, hands off.
    expect(b?.status).toBe("sending");
  });

  it("leaves pre-session bubbles that already hold a messageId alone", () => {
    const id = store.enqueueOutbound(PEER, "acked last run");
    store.markSent(PEER, id, "server-id-old");
    driver = startOutboxDriver(store, { sendDm, connect }, Date.now() + 60_000);
    const b = store.conversationsSorted()[0].messages.find((m) => m.id === id);
    // Relay-acked: already reachable by the retry paths, not an orphan.
    expect(b?.status).toBe("sending");
    expect(b?.messageId).toBe("server-id-old");
  });
});

describe("ChatStore — outbox bookkeeping", () => {
  it("enqueueOutbound appends a sending bubble with retry counter zero", () => {
    const id = store.enqueueOutbound(PEER, "hello");
    const conv = store.conversationsSorted()[0];
    const bubble = conv.messages.find((m) => m.id === id);
    expect(bubble?.status).toBe("sending");
    expect(bubble?.retryAttempts).toBe(0);
    expect(bubble?.mine).toBe(true);
  });

  it("markSent binds the daemon-assigned messageId without leaving sending", () => {
    const id = store.enqueueOutbound(PEER, "hello");
    store.markFailed(PEER, id, "boom");
    store.markSent(PEER, id, "server-id-1");
    const b = store.conversationsSorted()[0].messages[0];
    // A successful retry clears the failure and re-enters in-flight.
    expect(b.status).toBe("sending");
    expect(b.messageId).toBe("server-id-1");
    expect(b.failureReason).toBeUndefined();
  });

  it("markDelivered locates the bubble by messageId and flips it", () => {
    const id = store.enqueueOutbound(PEER, "hello");
    store.markSent(PEER, id, "server-id-2");
    store.markDelivered(PEER, "server-id-2");
    const b = store.conversationsSorted()[0].messages[0];
    expect(b.status).toBe("delivered");
  });

  it("markFailed increments retryAttempts and records the reason", () => {
    const id = store.enqueueOutbound(PEER, "hello");
    store.markFailed(PEER, id, "timeout");
    store.markFailed(PEER, id, "timeout");
    const b = store.conversationsSorted()[0].messages[0];
    expect(b.status).toBe("failed");
    expect(b.retryAttempts).toBe(2);
    expect(b.failureReason).toBe("timeout");
  });

  it("pendingOutbound includes every mine/sending bubble until receipt or failure", () => {
    store.enqueueOutbound(PEER, "one");
    const sentId = store.enqueueOutbound(PEER, "two");
    store.markSent(PEER, sentId, "server-id-2");
    store.recordDirectMessage({
      from: PEER, to: ME, body: "inbound", timestamp_ms: 1, message_id: "in-1",
    });
    // Both outbound bubbles are still pending — "two" has the relay ack
    // but no receipt yet, so it sits in the same state as "one".
    const pending = store.pendingOutbound();
    expect(pending).toHaveLength(2);
    // Once a receipt arrives, the bubble leaves the pending set.
    store.markDelivered(PEER, "server-id-2");
    expect(store.pendingOutbound()).toHaveLength(1);
    expect(store.pendingOutbound()[0].bubble.body).toBe("one");
  });
});

describe("startOutboxDriver — retries", () => {
  it("retries a failed bubble once the peer is marked online", async () => {
    const id = store.enqueueOutbound(PEER, "later");
    store.markFailed(PEER, id, "peer offline");

    sendDm.mockResolvedValue("server-id-1");
    driver = startOutboxDriver(store, { sendDm, connect });
    expect(sendDm).not.toHaveBeenCalled();

    store.applyPresenceTransition({ agent_id: PEER, event: "online" });
    await flushPromises();
    expect(sendDm).toHaveBeenCalledWith(PEER, "later");
    const b = store.conversationsSorted()[0].messages[0];
    // The driver landed the retry — bubble is back in flight,
    // awaiting the recipient's DeliveryReceipt to promote it.
    expect(b.status).toBe("sending");
    expect(b.messageId).toBe("server-id-1");
    expect(store.pendingOutbound()).toHaveLength(1);
  });

  it("does not retry pending (initial-send) bubbles", async () => {
    store.enqueueOutbound(PEER, "in flight");
    sendDm.mockResolvedValue(null);
    driver = startOutboxDriver(store, { sendDm, connect });
    store.applyPresenceTransition({ agent_id: PEER, event: "online" });
    await flushPromises();
    expect(sendDm).not.toHaveBeenCalled();
  });

  it("fires once per offline→online transition, not on subsequent ticks while online", async () => {
    const id = store.enqueueOutbound(PEER, "rate-limited");
    store.markFailed(PEER, id, "first try");
    sendDm.mockRejectedValue(new Error("still failing"));
    driver = startOutboxDriver(store, { sendDm, connect });
    store.applyPresenceTransition({ agent_id: PEER, event: "online" });
    await flushPromises();
    expect(sendDm).toHaveBeenCalledTimes(1);
    // Any number of further emits while peer stays online should NOT
    // trigger more retries — only the next offline→online edge does.
    store.applyPresenceTransition({ agent_id: PEER, event: "online" });
    store.applyPresenceTransition({ agent_id: PEER, event: "online" });
    await flushPromises();
    expect(sendDm).toHaveBeenCalledTimes(1);
  });

  it("re-fires on the next offline→online edge after a failed retry", async () => {
    const id = store.enqueueOutbound(PEER, "needs-second-chance");
    store.markFailed(PEER, id, "first try");
    sendDm.mockRejectedValueOnce(new Error("offline again"));
    sendDm.mockResolvedValueOnce("server-id-99");
    driver = startOutboxDriver(store, { sendDm, connect });
    store.applyPresenceTransition({ agent_id: PEER, event: "online" });
    await flushPromises();
    expect(sendDm).toHaveBeenCalledTimes(1);
    store.applyPresenceTransition({ agent_id: PEER, event: "offline" });
    store.applyPresenceTransition({ agent_id: PEER, event: "online" });
    await flushPromises();
    expect(sendDm).toHaveBeenCalledTimes(2);
    // Second attempt landed at the relay — bubble's awaiting receipt.
    const b = store.conversationsSorted()[0].messages[0];
    expect(b.status).toBe("sending");
    expect(b.messageId).toBe("server-id-99");
  });

  it("flushAll bypasses the edge gate for the manual Retry path", async () => {
    const id = store.enqueueOutbound(PEER, "stuck");
    store.markFailed(PEER, id, "boom");
    store.applyPresenceTransition({ agent_id: PEER, event: "online" });
    sendDm.mockRejectedValueOnce(new Error("first edge"));
    sendDm.mockResolvedValueOnce("ok");
    driver = startOutboxDriver(store, { sendDm, connect });
    await flushPromises();
    // After the initial edge fire, the bubble's still failed but the
    // edge has been consumed — further emits won't auto-retry.
    expect(sendDm).toHaveBeenCalledTimes(1);
    // Manual Retry: should run the second send regardless.
    driver.flushAll();
    await flushPromises();
    expect(sendDm).toHaveBeenCalledTimes(2);
    const b = store.conversationsSorted()[0].messages[0];
    expect(b.status).toBe("sending");
    expect(b.messageId).toBe("ok");
  });

  it("requeues to failed when a retry fails", async () => {
    const id = store.enqueueOutbound(PEER, "still-broken");
    store.markFailed(PEER, id, "first try");
    sendDm.mockRejectedValueOnce(new Error("still-broken"));
    driver = startOutboxDriver(store, { sendDm, connect });
    store.applyPresenceTransition({ agent_id: PEER, event: "online" });
    await flushPromises();
    const b = store.conversationsSorted()[0].messages[0];
    expect(b.status).toBe("failed");
    expect((b.retryAttempts ?? 0)).toBeGreaterThanOrEqual(2);
  });

  it("warms the QUIC link via connect() before each retry sendDm", async () => {
    const id = store.enqueueOutbound(PEER, "needs-warmup");
    store.markFailed(PEER, id, "cold link");
    const callOrder: string[] = [];
    connect.mockImplementation(async () => {
      callOrder.push("connect");
    });
    sendDm.mockImplementation(async () => {
      callOrder.push("send");
      return "ok";
    });
    driver = startOutboxDriver(store, { sendDm, connect });
    store.applyPresenceTransition({ agent_id: PEER, event: "online" });
    await flushPromises();
    expect(callOrder).toEqual(["connect", "send"]);
  });

  it("still sends if connect() fails — warmup is best-effort", async () => {
    const id = store.enqueueOutbound(PEER, "warmup-fails");
    store.markFailed(PEER, id, "first try");
    connect.mockRejectedValueOnce(new Error("no route"));
    sendDm.mockResolvedValue("ok-after-warmup-fail");
    driver = startOutboxDriver(store, { sendDm, connect });
    store.applyPresenceTransition({ agent_id: PEER, event: "online" });
    await flushPromises();
    expect(sendDm).toHaveBeenCalledTimes(1);
    const b = store.conversationsSorted()[0].messages[0];
    expect(b.status).toBe("sending");
    expect(b.messageId).toBe("ok-after-warmup-fail");
  });

  it("runs an initial tick on subscribe so restored failures kick off immediately", async () => {
    const id = store.enqueueOutbound(PEER, "from-last-session");
    store.markFailed(PEER, id, "offline last time");
    store.applyPresenceTransition({ agent_id: PEER, event: "online" });
    sendDm.mockResolvedValue("ok");
    driver = startOutboxDriver(store, { sendDm, connect });
    await flushPromises();
    expect(sendDm).toHaveBeenCalledTimes(1);
  });
});
