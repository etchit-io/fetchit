import { beforeEach, describe, expect, it } from "vitest";
import { ChatStore } from "./state";
import { MAX_BUBBLES_PER_DM, clearDms, loadDms } from "./persistence";

const ME = "a".repeat(64);
const OTHER_ME = "c".repeat(64);
const PEER = "b".repeat(64);

beforeEach(() => {
  localStorage.clear();
});

describe("ChatStore — persistence", () => {
  it("hydrates DM transcripts after re-creating the store with the same identity", () => {
    const s1 = new ChatStore();
    s1.setIdentity({ agent_id: ME, machine_id: "m" });
    s1.recordDirectMessage({
      from: PEER, to: ME, body: "first", timestamp_ms: 1, message_id: "m1",
    });
    s1.recordDirectMessage({
      from: ME, to: PEER, body: "reply", timestamp_ms: 2, message_id: "m2",
    });

    const s2 = new ChatStore();
    s2.setIdentity({ agent_id: ME, machine_id: "m" });
    const conv = s2.conversationsSorted()[0];
    expect(conv.messages.map((m) => m.body)).toEqual(["first", "reply"]);
    expect(conv.lastActivityMs).toBe(2);
  });

  it("does not leak transcripts across identities", () => {
    const s1 = new ChatStore();
    s1.setIdentity({ agent_id: ME, machine_id: "m" });
    s1.recordDirectMessage({
      from: PEER, to: ME, body: "private", timestamp_ms: 1, message_id: "m1",
    });
    const s2 = new ChatStore();
    s2.setIdentity({ agent_id: OTHER_ME, machine_id: "n" });
    expect(s2.conversationsSorted()).toHaveLength(0);
  });

  it("caps persisted bubbles per peer at MAX_BUBBLES_PER_DM", () => {
    const s = new ChatStore();
    s.setIdentity({ agent_id: ME, machine_id: "m" });
    for (let i = 0; i < MAX_BUBBLES_PER_DM + 50; i += 1) {
      s.recordDirectMessage({
        from: PEER, to: ME, body: `n${i}`, timestamp_ms: i, message_id: `id${i}`,
      });
    }
    const reloaded = loadDms(ME).get(PEER);
    expect(reloaded?.messages.length).toBe(MAX_BUBBLES_PER_DM);
    expect(reloaded?.messages[0].body).toBe(`n50`);
  });

  it("persists unread + lastActivity and zeros unread when activated", () => {
    const s = new ChatStore();
    s.setIdentity({ agent_id: ME, machine_id: "m" });
    s.recordDirectMessage({
      from: PEER, to: ME, body: "x", timestamp_ms: 5, message_id: "a",
    });
    s.recordDirectMessage({
      from: PEER, to: ME, body: "y", timestamp_ms: 6, message_id: "b",
    });
    let stored = loadDms(ME).get(PEER);
    expect(stored?.unread).toBe(2);
    expect(stored?.lastActivityMs).toBe(6);

    s.setActive({ kind: "dm", peer: PEER });
    stored = loadDms(ME).get(PEER);
    expect(stored?.unread).toBe(0);
  });

  it("dedupes by message_id when the same DM is recorded twice", () => {
    const s = new ChatStore();
    s.setIdentity({ agent_id: ME, machine_id: "m" });
    const dm = {
      from: PEER, to: ME, body: "echo", timestamp_ms: 1, message_id: "dup",
    };
    s.recordDirectMessage(dm);
    s.recordDirectMessage(dm);
    expect(s.conversationsSorted()[0].messages).toHaveLength(1);
  });

  it("clearDmTranscript wipes the conversation in memory and on disk", () => {
    const s = new ChatStore();
    s.setIdentity({ agent_id: ME, machine_id: "m" });
    s.recordDirectMessage({
      from: PEER, to: ME, body: "gone", timestamp_ms: 1, message_id: "m1",
    });
    s.clearDmTranscript(PEER);
    expect(s.conversationsSorted()).toHaveLength(0);
    expect(loadDms(ME).has(PEER)).toBe(false);
  });

  it("clearDms removes the full per-identity blob", () => {
    const s = new ChatStore();
    s.setIdentity({ agent_id: ME, machine_id: "m" });
    s.recordDirectMessage({
      from: PEER, to: ME, body: "x", timestamp_ms: 1, message_id: "m1",
    });
    clearDms(ME);
    expect(loadDms(ME).size).toBe(0);
  });
});
