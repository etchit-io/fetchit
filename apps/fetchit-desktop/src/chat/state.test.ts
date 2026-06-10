import { beforeEach, describe, expect, it, vi } from "vitest";
import { ChatStore, convKey, quotedRef } from "./state";

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

describe("ChatStore — reply quoting", () => {
  const REF = { messageId: "p1", senderName: "Bob", preview: "the parent" };

  it("enqueueOutbound stamps replyTo onto the optimistic bubble", () => {
    const s = new ChatStore();
    s.setIdentity({ agent_id: ME, machine_id: "m" });
    const id = s.enqueueOutbound(PEER, "a reply", REF);
    const conv = s.conversationsSorted()[0];
    const b = conv.messages.find((m) => m.id === id)!;
    expect(b.replyTo).toEqual(REF);
  });

  it("replyTo survives the localStorage round-trip", () => {
    const s = new ChatStore();
    s.setIdentity({ agent_id: ME, machine_id: "m" });
    s.enqueueOutbound(PEER, "a reply", REF);

    const reloaded = new ChatStore();
    reloaded.setIdentity({ agent_id: ME, machine_id: "m" });
    const conv = reloaded.conversationsSorted()[0];
    expect(conv.messages[0].replyTo).toEqual(REF);
  });

  it("inbound reply reconstructs the quote from my own sent parent", () => {
    const s = new ChatStore();
    s.setIdentity({ agent_id: ME, machine_id: "m" });
    const mine = s.enqueueOutbound(PEER, "the parent");
    s.markSent(PEER, mine, "daemon-1");
    s.recordDirectMessage({
      from: PEER,
      to: ME,
      body: "the answer",
      timestamp_ms: 5,
      message_id: "m9",
      reply_to_message_id: "daemon-1",
    });
    const conv = s.conversationsSorted()[0];
    const reply = conv.messages.find((m) => m.id === "m9")!;
    expect(reply.replyTo).toBeDefined();
    expect(reply.replyTo!.senderName).toBe("You");
    expect(reply.replyTo!.preview).toBe("the parent");
  });

  it("inbound reply quoting the peer's own earlier message names the peer", () => {
    const s = new ChatStore();
    s.setIdentity({ agent_id: ME, machine_id: "m" });
    s.recordDirectMessage({
      from: PEER,
      to: ME,
      body: "peer parent",
      timestamp_ms: 4,
      message_id: "p1",
    });
    s.recordDirectMessage({
      from: PEER,
      to: ME,
      body: "follow-up",
      timestamp_ms: 5,
      message_id: "p2",
      reply_to_message_id: "p1",
    });
    const conv = s.conversationsSorted()[0];
    const reply = conv.messages.find((m) => m.id === "p2")!;
    expect(reply.replyTo!.senderName).toBe(conv.title);
    expect(reply.replyTo!.preview).toBe("peer parent");
  });

  it("inbound reply to an unknown parent falls back to an honest placeholder", () => {
    const s = new ChatStore();
    s.setIdentity({ agent_id: ME, machine_id: "m" });
    s.recordDirectMessage({
      from: PEER,
      to: ME,
      body: "re",
      timestamp_ms: 5,
      message_id: "m9",
      reply_to_message_id: "gone-1",
    });
    const conv = s.conversationsSorted()[0];
    const reply = conv.messages.find((m) => m.id === "m9")!;
    expect(reply.replyTo!.preview).toBe("(message unavailable)");
  });

  it("quotedRef prefers the daemon messageId and truncates long bodies to one line", () => {
    const short = quotedRef(
      {
        id: "local-1",
        messageId: "daemon-9",
        from: PEER,
        body: "line one\nline two",
        timestampMs: 0,
        mine: false,
      },
      "Bob",
    );
    expect(short.messageId).toBe("daemon-9");
    expect(short.senderName).toBe("Bob");
    expect(short.preview).toBe("line one line two");

    const long = quotedRef(
      {
        id: "local-2",
        from: PEER,
        body: "x".repeat(300),
        timestampMs: 0,
        mine: false,
      },
      "Bob",
    );
    expect(long.messageId).toBe("local-2");
    expect(long.preview.length).toBeLessThanOrEqual(120);
    expect(long.preview.endsWith("…")).toBe(true);
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

  it("a successful send does NOT flip presence — relay PresenceUpdate is the source of truth", () => {
    // Regression: the legacy markDelivered path called touchPresence as
    // a "side-evidence" boost. That painted contacts green during the
    // 15-minute relay transit-buffer window even when they were offline.
    // The relay's own PresenceUpdate is now the only signal.
    const s = new ChatStore();
    s.setIdentity({ agent_id: ME, machine_id: "m" });
    const oldSeconds = Math.floor((Date.now() - 10 * 60_000) / 1000);
    s.loadPresence([{ agent_id: PEER, last_seen: oldSeconds }]);
    expect(s.isOnline(PEER)).toBe(false);
    const id = s.enqueueOutbound(PEER, "hi");
    s.markSent(PEER, id, "msg-id-1");
    expect(s.isOnline(PEER)).toBe(false);
  });

  it("setRelayPresence flips the dot to the relay's authoritative signal", () => {
    const s = new ChatStore();
    s.setIdentity({ agent_id: ME, machine_id: "m" });
    expect(s.isOnline(PEER)).toBe(false);
    s.setRelayPresence(PEER, true);
    expect(s.isOnline(PEER)).toBe(true);
    s.setRelayPresence(PEER, false);
    expect(s.isOnline(PEER)).toBe(false);
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
    const deliveredId = s.enqueueOutbound(PEER, "ok");
    s.markSent(PEER, deliveredId, "msg-id-ok");
    s.markDelivered(PEER, "msg-id-ok");
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

describe("ChatStore — denylist (M3 G2)", () => {
  const A = "a".repeat(64);
  const B = "b".repeat(64);

  it("an unknown agent is not denylisted", () => {
    const s = new ChatStore();
    expect(s.isDenylisted(A)).toBe(false);
  });

  it("applyDenylistUpdate adds and removes agents", () => {
    const s = new ChatStore();
    s.applyDenylistUpdate([A, B], []);
    expect(s.isDenylisted(A)).toBe(true);
    expect(s.isDenylisted(B)).toBe(true);
    s.applyDenylistUpdate([], [A]);
    expect(s.isDenylisted(A)).toBe(false);
    expect(s.isDenylisted(B)).toBe(true);
  });

  it("re-adding an already-blocked agent does not emit (idempotent)", () => {
    const s = new ChatStore();
    s.applyDenylistUpdate([A], []);
    const notify = vi.fn();
    s.subscribe(notify);
    s.applyDenylistUpdate([A], []);
    expect(notify).not.toHaveBeenCalled();
    expect(s.isDenylisted(A)).toBe(true);
  });

  it("removing an absent agent does not emit", () => {
    const s = new ChatStore();
    const notify = vi.fn();
    s.subscribe(notify);
    s.applyDenylistUpdate([], [A]);
    expect(notify).not.toHaveBeenCalled();
  });

  it("a real transition emits once", () => {
    const s = new ChatStore();
    const notify = vi.fn();
    s.subscribe(notify);
    s.applyDenylistUpdate([A], []);
    expect(notify).toHaveBeenCalledTimes(1);
  });
});

describe("convKey", () => {
  it("namespaces DM and group keys", () => {
    expect(convKey({ kind: "dm", peer: "p1" })).toBe("dm:p1");
    expect(convKey({ kind: "group", groupId: "g1" })).toBe("g:g1");
  });
});

describe("ChatStore — daemon status", () => {
  it("starts with null status so the header pill stays hidden during boot", () => {
    const s = new ChatStore();
    expect(s.getDaemonStatus()).toBeNull();
  });

  it("records the latest daemon status emitted by the backend watcher", () => {
    const s = new ChatStore();
    s.setDaemonStatus("connected");
    expect(s.getDaemonStatus()).toBe("connected");
    s.setDaemonStatus("reconnecting");
    expect(s.getDaemonStatus()).toBe("reconnecting");
    s.setDaemonStatus("down");
    expect(s.getDaemonStatus()).toBe("down");
  });

  it("only notifies subscribers when the status value actually changes", () => {
    // Without this guard, duplicate edge-emits from the backend would
    // trigger every store subscriber on every poll cycle — including
    // the conversation pane's bubble-list short-circuit, defeating
    // the chat-bubble-pop fix from c102219.
    const s = new ChatStore();
    let calls = 0;
    s.subscribe(() => {
      calls++;
    });
    s.setDaemonStatus("connected");
    s.setDaemonStatus("connected");
    s.setDaemonStatus("connected");
    expect(calls).toBe(1);
    s.setDaemonStatus("reconnecting");
    expect(calls).toBe(2);
  });
});
