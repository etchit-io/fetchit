import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const maybeNotifyMock = vi.fn();
vi.mock("./notify", () => ({
  maybeNotifyInboundDm: (...args: unknown[]) => maybeNotifyMock(...args),
}));

import { applyChatEvent } from "./events";
import { ChatStore } from "./state";

const ME = "a".repeat(64);
const PEER = "b".repeat(64);

let store: ChatStore;

beforeEach(() => {
  localStorage.clear();
  maybeNotifyMock.mockReset();
  store = new ChatStore();
  store.setIdentity({ agent_id: ME, machine_id: "m" });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("applyChatEvent", () => {
  it("records direct_message into the store and fires notify hook", () => {
    applyChatEvent(store, {
      kind: "direct_message",
      from: PEER,
      to: ME,
      body: "hello",
      timestamp_ms: 1,
      message_id: "m1",
    });
    expect(store.conversationsSorted()).toHaveLength(1);
    expect(maybeNotifyMock).toHaveBeenCalledTimes(1);
  });

  it("ignores x0xd-source presence transitions (they ride chat:presence:x0x now)", () => {
    // x0xd's gossip-derived presence is intentionally dropped from
    // `chat:event` since the relay's `PresenceUpdate` is the only
    // signal painted on the dot. The test guards against accidental
    // re-introduction of the false-positive flip.
    applyChatEvent(store, {
      kind: "presence",
      agent_id: PEER,
      event: "online",
      reachable: true,
    });
    expect(store.isOnline(PEER)).toBe(false);
  });

  it("upserts contacts on contact_added", () => {
    applyChatEvent(store, {
      kind: "contact_added",
      agent_id: PEER,
      trust_level: "trusted",
      label: "Bob",
    });
    expect(store.contact(PEER)?.label).toBe("Bob");
  });

  it("removes contacts on contact_removed", () => {
    store.upsertContact({ agent_id: PEER, trust_level: "trusted", label: "Bob" });
    applyChatEvent(store, { kind: "contact_removed", agent_id: PEER });
    expect(store.contact(PEER)).toBeUndefined();
  });

  it("silently ignores unknown kinds", () => {
    expect(() =>
      applyChatEvent(store, {
        kind: "other",
        event_name: "weird",
        data: {},
      }),
    ).not.toThrow();
  });
});
