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

describe("ChatStore — outbox bookkeeping", () => {
  it("enqueueOutbound appends a pending bubble with retry counter zero", () => {
    const id = store.enqueueOutbound(PEER, "hello");
    const conv = store.conversationsSorted()[0];
    const bubble = conv.messages.find((m) => m.id === id);
    expect(bubble?.status).toBe("pending");
    expect(bubble?.retryAttempts).toBe(0);
    expect(bubble?.mine).toBe(true);
  });

  it("markDelivered flips status and clears any failureReason", () => {
    const id = store.enqueueOutbound(PEER, "hello");
    store.markFailed(PEER, id, "boom");
    store.markDelivered(PEER, id);
    const b = store.conversationsSorted()[0].messages[0];
    expect(b.status).toBe("delivered");
    expect(b.failureReason).toBeUndefined();
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

  it("pendingOutbound returns only mine/non-delivered bubbles", () => {
    store.enqueueOutbound(PEER, "one");
    const delivered = store.enqueueOutbound(PEER, "two");
    store.markDelivered(PEER, delivered);
    store.recordDirectMessage({
      from: PEER, to: ME, body: "inbound", timestamp_ms: 1, message_id: "in-1",
    });
    const pending = store.pendingOutbound();
    expect(pending).toHaveLength(1);
    expect(pending[0].bubble.body).toBe("one");
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
    expect(store.pendingOutbound()).toHaveLength(0);
    const b = store.conversationsSorted()[0].messages[0];
    expect(b.status).toBe("delivered");
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
    sendDm.mockResolvedValueOnce("delivered");
    driver = startOutboxDriver(store, { sendDm, connect });
    store.applyPresenceTransition({ agent_id: PEER, event: "online" });
    await flushPromises();
    expect(sendDm).toHaveBeenCalledTimes(1);
    store.applyPresenceTransition({ agent_id: PEER, event: "offline" });
    store.applyPresenceTransition({ agent_id: PEER, event: "online" });
    await flushPromises();
    expect(sendDm).toHaveBeenCalledTimes(2);
    expect(store.pendingOutbound()).toHaveLength(0);
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
    expect(store.pendingOutbound()).toHaveLength(0);
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
    sendDm.mockResolvedValue("delivered");
    driver = startOutboxDriver(store, { sendDm, connect });
    store.applyPresenceTransition({ agent_id: PEER, event: "online" });
    await flushPromises();
    expect(sendDm).toHaveBeenCalledTimes(1);
    expect(store.pendingOutbound()).toHaveLength(0);
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
