import { beforeEach, describe, expect, it } from "vitest";
import { ChatStore, convKey } from "./state";

const ME = "a".repeat(64);
const PEER = "b".repeat(64);

beforeEach(() => {
  localStorage.clear();
});

describe("ChatStore — DM bookkeeping", () => {
  it("records an inbound DM under the peer's conversation", () => {
    const s = new ChatStore();
    s.setIdentity({ agent_id: ME, machine_id: "m" });
    s.recordDirectMessage({
      from: PEER,
      to: ME,
      body: "hi",
      timestamp_ms: 1,
      message_id: "m1",
    });
    const convs = s.conversationsSorted();
    expect(convs).toHaveLength(1);
    expect(convs[0].key).toEqual({ kind: "dm", peer: PEER });
    expect(convs[0].messages).toHaveLength(1);
    expect(convs[0].messages[0].mine).toBe(false);
  });

  it("flags outbound DMs as mine", () => {
    const s = new ChatStore();
    s.setIdentity({ agent_id: ME, machine_id: "m" });
    s.recordDirectMessage({
      from: ME,
      to: PEER,
      body: "yo",
      timestamp_ms: 2,
      message_id: "m2",
    });
    const conv = s.conversationsSorted()[0];
    expect(conv.messages[0].mine).toBe(true);
  });

  it("increments unread for inbound messages on inactive conversations", () => {
    const s = new ChatStore();
    s.setIdentity({ agent_id: ME, machine_id: "m" });
    s.setPanelVisible(true);
    s.recordDirectMessage({
      from: PEER, to: ME, body: "x", timestamp_ms: 1, message_id: "1",
    });
    s.recordDirectMessage({
      from: PEER, to: ME, body: "y", timestamp_ms: 2, message_id: "2",
    });
    expect(s.conversationsSorted()[0].unread).toBe(2);
  });

  it("clears unread when the conversation becomes active and panel is visible", () => {
    const s = new ChatStore();
    s.setIdentity({ agent_id: ME, machine_id: "m" });
    s.setPanelVisible(true);
    s.recordDirectMessage({
      from: PEER, to: ME, body: "x", timestamp_ms: 1, message_id: "1",
    });
    s.setActive({ kind: "dm", peer: PEER });
    expect(s.conversationsSorted()[0].unread).toBe(0);
  });

  it("bumps unread for active conv when the panel is closed", () => {
    const s = new ChatStore();
    s.setIdentity({ agent_id: ME, machine_id: "m" });
    s.setActive({ kind: "dm", peer: PEER });
    // Panel still closed — inbound to "active" conv still counts as
    // unread because the user can't actually see anything.
    s.recordDirectMessage({
      from: PEER, to: ME, body: "y", timestamp_ms: 1, message_id: "1",
    });
    expect(s.conversationsSorted()[0].unread).toBe(1);
  });

  it("setPanelVisible(true) clears unread for the active conv on open", () => {
    const s = new ChatStore();
    s.setIdentity({ agent_id: ME, machine_id: "m" });
    s.setActive({ kind: "dm", peer: PEER });
    s.recordDirectMessage({
      from: PEER, to: ME, body: "y", timestamp_ms: 1, message_id: "1",
    });
    expect(s.conversationsSorted()[0].unread).toBe(1);
    s.setPanelVisible(true);
    expect(s.conversationsSorted()[0].unread).toBe(0);
  });
});

describe("ChatStore — presence", () => {
  it("marks an agent online on transition", () => {
    const s = new ChatStore();
    s.applyPresenceTransition({ agent_id: PEER, event: "online" });
    expect(s.isOnline(PEER)).toBe(true);
  });

  it("marks offline on offline transition", () => {
    const s = new ChatStore();
    s.applyPresenceTransition({ agent_id: PEER, event: "online" });
    s.applyPresenceTransition({ agent_id: PEER, event: "offline" });
    expect(s.isOnline(PEER)).toBe(false);
  });

  it("notifies subscribers on every presence transition", () => {
    const s = new ChatStore();
    let calls = 0;
    s.subscribe(() => {
      calls += 1;
    });
    const before = calls;
    s.applyPresenceTransition({ agent_id: PEER, event: "online" });
    s.applyPresenceTransition({ agent_id: PEER, event: "offline" });
    expect(calls - before).toBe(2);
  });

  it("loadPresence resets and re-seeds the online map", () => {
    const s = new ChatStore();
    s.applyPresenceTransition({ agent_id: PEER, event: "online" });
    expect(s.isOnline(PEER)).toBe(true);
    s.loadPresence([]);
    expect(s.isOnline(PEER)).toBe(false);
  });

  it("treats peers with a stale last_seen as offline (client-side fallback)", () => {
    const s = new ChatStore();
    const oldSeconds = Math.floor((Date.now() - 5 * 60_000) / 1000);
    s.loadPresence([{ agent_id: PEER, last_seen: oldSeconds }]);
    expect(s.isOnline(PEER)).toBe(false);
  });

  it("keeps peers with a recent last_seen online", () => {
    const s = new ChatStore();
    const recentSeconds = Math.floor(Date.now() / 1000);
    s.loadPresence([{ agent_id: PEER, last_seen: recentSeconds }]);
    expect(s.isOnline(PEER)).toBe(true);
  });

  it("a successful send refreshes the staleness clock via touchPresence", () => {
    const s = new ChatStore();
    s.setIdentity({ agent_id: ME, machine_id: "m" });
    const oldSeconds = Math.floor((Date.now() - 10 * 60_000) / 1000);
    s.loadPresence([{ agent_id: PEER, last_seen: oldSeconds }]);
    expect(s.isOnline(PEER)).toBe(false);
    const id = s.enqueueOutbound(PEER, "hi");
    s.markDelivered(PEER, id);
    expect(s.isOnline(PEER)).toBe(true);
  });

  it("a fresh online transition resets the staleness clock", () => {
    const s = new ChatStore();
    const oldSeconds = Math.floor((Date.now() - 5 * 60_000) / 1000);
    s.loadPresence([{ agent_id: PEER, last_seen: oldSeconds }]);
    expect(s.isOnline(PEER)).toBe(false);
    s.applyPresenceTransition({ agent_id: PEER, event: "online" });
    expect(s.isOnline(PEER)).toBe(true);
  });

  it("mergePresenceSnapshot promotes a peer absent from the live map", () => {
    const s = new ChatStore();
    const nowSeconds = Math.floor(Date.now() / 1000);
    s.mergePresenceSnapshot([{ agent_id: PEER, last_seen: nowSeconds }]);
    expect(s.isOnline(PEER)).toBe(true);
  });

  it("mergePresenceSnapshot refreshes a stale peer whose snapshot is newer", () => {
    const s = new ChatStore();
    s.loadPresence([{
      agent_id: PEER,
      last_seen: Math.floor((Date.now() - 5 * 60_000) / 1000),
    }]);
    expect(s.isOnline(PEER)).toBe(false);
    const fresh = Math.floor(Date.now() / 1000);
    s.mergePresenceSnapshot([{ agent_id: PEER, last_seen: fresh }]);
    expect(s.isOnline(PEER)).toBe(true);
  });

  it("resetFailedRetryCounters zeros the counter on failed bubbles only", () => {
    const s = new ChatStore();
    s.setIdentity({ agent_id: ME, machine_id: "m" });
    const stuck = s.enqueueOutbound(PEER, "stuck");
    s.markFailed(PEER, stuck, "first");
    s.markFailed(PEER, stuck, "second");
    s.markFailed(PEER, stuck, "third");
    const delivered = s.enqueueOutbound(PEER, "ok");
    s.markDelivered(PEER, delivered);
    expect(s.resetFailedRetryCounters()).toBe(1);
    const failedBubble = s
      .conversationsSorted()[0]
      .messages.find((m) => m.id === stuck);
    expect(failedBubble?.retryAttempts).toBe(0);
    expect(failedBubble?.status).toBe("failed");
  });

  it("mergePresenceSnapshot does not regress a fresher SSE-set entry", () => {
    const s = new ChatStore();
    s.applyPresenceTransition({ agent_id: PEER, event: "online" });
    const fresh = Date.now();
    // Snapshot's last_seen is older than the SSE-set timestamp.
    s.mergePresenceSnapshot([{
      agent_id: PEER,
      last_seen: Math.floor((fresh - 30_000) / 1000),
    }]);
    expect(s.isOnline(PEER)).toBe(true);
  });
});

describe("ChatStore — contacts", () => {
  it("loads and removes contacts", () => {
    const s = new ChatStore();
    s.loadContacts([
      { agent_id: PEER, trust_level: "trusted", label: "Bob" },
    ]);
    expect(s.allContacts()).toHaveLength(1);
    s.removeContact(PEER);
    expect(s.allContacts()).toHaveLength(0);
  });

  it("sorts contacts by label alphabetically", () => {
    const s = new ChatStore();
    s.loadContacts([
      { agent_id: "c".repeat(64), trust_level: "known", label: "Zed" },
      { agent_id: "d".repeat(64), trust_level: "known", label: "Alice" },
    ]);
    const names = s.allContacts().map((c) => c.label);
    expect(names).toEqual(["Alice", "Zed"]);
  });
});

describe("convKey", () => {
  it("namespaces DM and group keys", () => {
    expect(convKey({ kind: "dm", peer: "p1" })).toBe("dm:p1");
    expect(convKey({ kind: "group", groupId: "g1" })).toBe("g:g1");
  });
});
