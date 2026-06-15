import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const maybeNotifyMock = vi.fn();
vi.mock("./notify", () => ({
  maybeNotifyInboundDm: (...args: unknown[]) => maybeNotifyMock(...args),
}));

import {
  applyChatEvent,
  applyDenylistUpdateEvent,
  applyRelayStatusEvent,
  makeRelayDenylistedHandler,
  makeRelayFailoverHandler,
  projectPendingContact,
  warnEventToCopy,
} from "./events";
import { ChatStore, TRANSIENT_NOTICE_MS } from "./state";

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

describe("projectPendingContact", () => {
  // The chat:contact-request event carries the full Rust Conversation
  // struct. Pin the field walk so future schema drift surfaces here
  // before it reaches the UI as a missing badge.

  function welcome(members: Array<{ agentId: string }>): {
    group_id_hex: string;
    members: Array<{ devices: Array<{ agent_id_hex: string }> }>;
  } {
    return {
      group_id_hex: "deadbeef".repeat(8),
      members: members.map((m) => ({
        devices: [{ agent_id_hex: m.agentId }],
      })),
    };
  }

  it("picks the first non-self member as the peer", () => {
    const entry = projectPendingContact(
      welcome([{ agentId: ME }, { agentId: PEER }]),
      ME,
      1234,
    );
    expect(entry).toEqual({
      groupIdHex: "deadbeef".repeat(8),
      peerAgentId: PEER,
      arrivedAtMs: 1234,
    });
  });

  it("returns null when no non-self member is present", () => {
    // Degenerate welcome with only the local user — should not
    // generate a self-targeted contact request.
    const entry = projectPendingContact(welcome([{ agentId: ME }]), ME, 1);
    expect(entry).toBeNull();
  });

  it("returns null when members is missing or empty", () => {
    const a = projectPendingContact(
      { group_id_hex: "x", members: [] },
      ME,
      1,
    );
    expect(a).toBeNull();
  });

  it("with null local identity, the listener drops the event upstream — projection still picks the first member if called", () => {
    // The events.ts listener guards on myId() and drops pre-identity
    // events entirely. If projectPendingContact is ever called with
    // a null `me` directly, it falls back to "first non-self" which
    // with null === any guard always rejecting is still the first
    // member. This test pins the helper's behavior; the listener
    // owns the bootstrap-race guard.
    const entry = projectPendingContact(
      welcome([{ agentId: PEER }]),
      null,
      1,
    );
    expect(entry?.peerAgentId).toBe(PEER);
  });
});

describe("ChatStore — pending contact requests", () => {
  it("addPendingContact + removePendingContact emit subscribers", () => {
    const notify = vi.fn();
    store.subscribe(notify);
    store.addPendingContact({
      groupIdHex: "g1",
      peerAgentId: PEER,
      arrivedAtMs: 1,
    });
    expect(store.allPendingContacts()).toHaveLength(1);
    expect(notify).toHaveBeenCalled();
    notify.mockClear();
    store.removePendingContact("g1");
    expect(store.allPendingContacts()).toHaveLength(0);
    expect(notify).toHaveBeenCalled();
  });

  it("addPendingContact is idempotent on groupIdHex (re-emit overwrites)", () => {
    store.addPendingContact({
      groupIdHex: "g1",
      peerAgentId: PEER,
      arrivedAtMs: 1,
    });
    store.addPendingContact({
      groupIdHex: "g1",
      peerAgentId: PEER,
      arrivedAtMs: 99,
    });
    const all = store.allPendingContacts();
    expect(all).toHaveLength(1);
    expect(all[0].arrivedAtMs).toBe(99);
  });

  it("sorts pending contacts newest first", () => {
    store.addPendingContact({
      groupIdHex: "g1",
      peerAgentId: PEER,
      arrivedAtMs: 1,
    });
    store.addPendingContact({
      groupIdHex: "g2",
      peerAgentId: "c".repeat(64),
      arrivedAtMs: 100,
    });
    const all = store.allPendingContacts();
    expect(all[0].groupIdHex).toBe("g2");
    expect(all[1].groupIdHex).toBe("g1");
  });

  it("removePendingContact on absent key is a silent no-op", () => {
    const notify = vi.fn();
    store.subscribe(notify);
    store.removePendingContact("never-added");
    expect(notify).not.toHaveBeenCalled();
  });
});

describe("warnEventToCopy", () => {
  it("translates stale_epoch into rekey-in-progress copy", () => {
    expect(warnEventToCopy({ kind: "stale_epoch" })).toContain("refreshing keys");
  });

  it("translates kem_decap_failed into a sender-rekey hint", () => {
    expect(warnEventToCopy({ kind: "kem_decap_failed" })).toContain("rekey");
  });

  it("translates aead_open_failed into an authentication-failed line", () => {
    expect(warnEventToCopy({ kind: "aead_open_failed" })).toContain("authentication");
  });

  it("translates private_group_decrypt_failed into an out-of-date-key line", () => {
    expect(
      warnEventToCopy({ kind: "private_group_decrypt_failed", group_id: "g", error: "boom" }),
    ).toContain("out of date");
  });

  it("falls back to a generic 'something went wrong' for unknown kinds", () => {
    expect(warnEventToCopy({ kind: "novel_failure_mode" })).toContain("novel_failure_mode");
  });
});

describe("applyRelayStatusEvent", () => {
  it("maps live transitions onto the relay pill state", () => {
    applyRelayStatusEvent(store, { kind: "connecting" });
    expect(store.getRelayStatus()).toBe("connecting");
    applyRelayStatusEvent(store, { kind: "connected" });
    expect(store.getRelayStatus()).toBe("connected");
    applyRelayStatusEvent(store, { kind: "reconnecting", reason: "io" });
    expect(store.getRelayStatus()).toBe("reconnecting");
    expect(store.allNotices()).toHaveLength(0);
  });

  it("terminal disconnect sets down and raises the lost-connection notice", () => {
    applyRelayStatusEvent(store, {
      kind: "permanently_disconnected",
      reason: "gave up",
      attempts: 20,
    });
    expect(store.getRelayStatus()).toBe("down");
    const notices = store.allNotices();
    expect(notices).toHaveLength(1);
    expect(notices[0]!.body).toContain("Lost connection");
  });

  it("drops unknown kinds without touching the store", () => {
    applyRelayStatusEvent(store, { kind: "future_state" });
    expect(store.getRelayStatus()).toBeNull();
    expect(store.allNotices()).toHaveLength(0);
  });
});

describe("applyDenylistUpdateEvent (M3 G2)", () => {
  const A = "a".repeat(64);

  it("applies an agent_id-kind transition to the store", () => {
    applyDenylistUpdateEvent(store, { kind: "agent_id", added: [A], removed: [] });
    expect(store.isDenylisted(A)).toBe(true);
  });

  it("ignores non-agent_id kinds (xor_name / relay_url / actor_url)", () => {
    applyDenylistUpdateEvent(store, { kind: "relay_url", added: [A], removed: [] });
    applyDenylistUpdateEvent(store, { kind: "xor_name", added: [A], removed: [] });
    applyDenylistUpdateEvent(store, { kind: "actor_url", added: [A], removed: [] });
    expect(store.isDenylisted(A)).toBe(false);
  });

  it("tolerates missing added/removed arrays", () => {
    applyDenylistUpdateEvent(store, { kind: "agent_id" } as never);
    expect(store.isDenylisted(A)).toBe(false);
  });
});

describe("makeRelayDenylistedHandler (M3 G1)", () => {
  const RELAY = "wss://nyc.etchit.io/v1/ws";

  it("pushes a warn notice naming the relay URL on first fire", () => {
    const handler = makeRelayDenylistedHandler(store);
    handler(RELAY);
    const notices = store.allNotices();
    expect(notices).toHaveLength(1);
    expect(notices[0].severity).toBe("warn");
    expect(notices[0].body).toContain(RELAY);
    expect(notices[0].body).toContain("Settings → Network");
  });

  it("dedupes by URL — a repeated fire for the same relay is a no-op", () => {
    const handler = makeRelayDenylistedHandler(store);
    handler(RELAY);
    handler(RELAY);
    handler(RELAY);
    // Idempotency note from G1 review: a Lagged-recovery or duplicate
    // `added` re-fires the callback; the banner must not stack.
    expect(store.allNotices()).toHaveLength(1);
  });

  it("surfaces distinct relays independently", () => {
    const handler = makeRelayDenylistedHandler(store);
    handler(RELAY);
    handler("wss://fra.etchit.io/v1/ws");
    expect(store.allNotices()).toHaveLength(2);
  });
});

describe("makeRelayFailoverHandler (T9)", () => {
  const NEW_RELAY = "http://159.89.11.217:8088";

  it("pushes an info notice naming the new relay on migrated", () => {
    const handler = makeRelayFailoverHandler(store);
    handler({ kind: "migrated", from: "http://old:8088", to: NEW_RELAY });
    const notices = store.allNotices();
    expect(notices).toHaveLength(1);
    expect(notices[0].severity).toBe("info");
    expect(notices[0].body).toContain(NEW_RELAY);
  });

  it("pushes a warn notice on failed", () => {
    const handler = makeRelayFailoverHandler(store);
    handler({ kind: "failed", dead: "http://dead:8088" });
    const notices = store.allNotices();
    expect(notices).toHaveLength(1);
    expect(notices[0].severity).toBe("warn");
    expect(notices[0].body).toContain("Settings → Network");
  });

  it("ignores a migrated event missing the target url", () => {
    const handler = makeRelayFailoverHandler(store);
    handler({ kind: "migrated" });
    expect(store.allNotices()).toHaveLength(0);
  });
});

describe("ChatStore — transient notices", () => {
  it("pushNotice appends a notice and emits subscribers", () => {
    const notify = vi.fn();
    store.subscribe(notify);
    const id = store.pushNotice("warn", "a thing happened");
    expect(id).toBeTruthy();
    expect(store.allNotices()).toHaveLength(1);
    expect(store.allNotices()[0].body).toBe("a thing happened");
    expect(notify).toHaveBeenCalled();
  });

  it("dismissNotice on a known id drops the entry and emits", () => {
    const id = store.pushNotice("warn", "x");
    const notify = vi.fn();
    store.subscribe(notify);
    store.dismissNotice(id);
    expect(store.allNotices()).toHaveLength(0);
    expect(notify).toHaveBeenCalled();
  });

  it("dismissNotice on an unknown id is a silent no-op", () => {
    const notify = vi.fn();
    store.subscribe(notify);
    store.dismissNotice("never-existed");
    expect(notify).not.toHaveBeenCalled();
  });

  it("auto-expires a notice after TRANSIENT_NOTICE_MS", () => {
    vi.useFakeTimers();
    try {
      store.pushNotice("warn", "ephemeral");
      expect(store.allNotices()).toHaveLength(1);
      vi.advanceTimersByTime(TRANSIENT_NOTICE_MS + 100);
      expect(store.allNotices()).toHaveLength(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("sorts notices newest first", () => {
    // Run entirely under fake timers so the auto-expire setTimeouts
    // scheduled by pushNotice don't leak real wall-clock timers into
    // subsequent tests (caught in adversarial review).
    vi.useFakeTimers();
    try {
      const id1 = store.pushNotice("info", "first");
      vi.setSystemTime(Date.now() + 10);
      const id2 = store.pushNotice("warn", "second");
      const all = store.allNotices();
      expect(all[0].id).toBe(id2);
      expect(all[1].id).toBe(id1);
    } finally {
      vi.useRealTimers();
    }
  });
});
