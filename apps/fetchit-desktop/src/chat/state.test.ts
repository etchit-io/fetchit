import { describe, expect, it } from "vitest";
import { ChatStore, convKey } from "./state";

const ME = "a".repeat(64);
const PEER = "b".repeat(64);

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
    s.recordDirectMessage({
      from: PEER, to: ME, body: "x", timestamp_ms: 1, message_id: "1",
    });
    s.recordDirectMessage({
      from: PEER, to: ME, body: "y", timestamp_ms: 2, message_id: "2",
    });
    expect(s.conversationsSorted()[0].unread).toBe(2);
  });

  it("clears unread when the conversation becomes active", () => {
    const s = new ChatStore();
    s.setIdentity({ agent_id: ME, machine_id: "m" });
    s.recordDirectMessage({
      from: PEER, to: ME, body: "x", timestamp_ms: 1, message_id: "1",
    });
    s.setActive({ kind: "dm", peer: PEER });
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
