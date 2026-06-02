// Direct unit tests for `mountConversation` — exercised against a real
// `ChatStore` so the seam that actually contains the unsubscribe logic
// is locked down. `panel.test.ts` mocks this module wholesale, so
// without the assertions below an accidental swap of `stopPolling` and
// `dispose` bodies would pass the panel suite while reproducing the
// bug `c05ffc0` (and `c05ffc0 / round 3`) was filed against.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("./api", () => ({
  dmConnect: vi.fn(() => Promise.resolve()),
  sendDm: vi.fn(() => Promise.resolve("msg-id")),
  sendGroupMessage: vi.fn(() => Promise.resolve()),
  groupHistory: vi.fn(() => Promise.resolve([])),
}));

import { mountConversation, type ConversationHandle } from "./conversation";
import { ChatStore } from "./state";
import { groupHistory as groupHistoryMock } from "./api";

let store: ChatStore;
let host: HTMLElement;
let handle: ConversationHandle;

const noopHandlers = {
  onAutonomi: () => {},
  onCard: () => {},
  onInvite: () => {},
  onProfile: () => {},
  onAddContact: () => {},
  onSetTrust: () => {},
  onRemoveContact: () => {},
  onLeaveGroup: () => {},
  resolveSenderName: () => "Tester",
};

beforeEach(() => {
  // ChatStore.persistDms writes to localStorage and rehydrates from it on
  // setIdentity. Without this clear, a `recordDirectMessage` from a prior
  // test sticks around in localStorage and re-loads into the next test's
  // fresh store — the DOM ends up with bubbles the test didn't put there.
  localStorage.clear();
  vi.useFakeTimers();
  vi.mocked(groupHistoryMock).mockClear();
  store = new ChatStore();
  store.setIdentity({
    agent_id: "a".repeat(64),
    user_id: "tester",
    machine_id: "0".repeat(64),
  });
  host = document.createElement("section");
  document.body.appendChild(host);
});

afterEach(() => {
  handle?.dispose();
  host.remove();
  // Clear any setInterval/setTimeout that fake-timer-mode tests
  // leaked so they don't bleed into the next test's render loop.
  vi.clearAllTimers();
  vi.useRealTimers();
});

describe("mountConversation — stopPolling vs dispose contract", () => {
  it("dispose() unsubscribes the render listener so further store ticks are no-ops", () => {
    handle = mountConversation(host, store, noopHandlers);
    // Visible-panel context — the render gate short-circuits while
    // hidden, so the test must keep the panel "shown" to observe DOM
    // writes attributable to the listener subscription.
    store.setPanelVisible(true);
    store.setActive({ kind: "dm", peer: "b".repeat(64) });
    const subjectEl = host.querySelector(
      ".chat-conv-header__subject",
    ) as HTMLElement;
    const titleBefore = subjectEl.textContent;

    handle.dispose();
    // After dispose, store mutations must not re-render the pane.
    store.setActive(null);
    expect(subjectEl.textContent).toBe(titleBefore);
  });

  it("stopPolling() leaves the render listener subscribed so reopens still update", () => {
    handle = mountConversation(host, store, noopHandlers);
    store.setPanelVisible(true);
    // Materialise conversations so `store.active()` resolves to a real
    // entry — `setActive` only stores the key string; the
    // conversations map is filled by `ensureDm` / `loadContacts` etc.
    const peerB = "b".repeat(64);
    const peerC = "c".repeat(64);
    store.ensureDm(peerB);
    store.ensureDm(peerC);
    store.setActive({ kind: "dm", peer: peerB });
    const subjectEl = host.querySelector(
      ".chat-conv-header__subject",
    ) as HTMLElement;
    const before = subjectEl.textContent;
    expect(before).not.toBe("");

    handle.stopPolling();
    // After stopPolling, store mutations MUST still render.
    store.setActive({ kind: "dm", peer: peerC });
    // The DM title falls back to a truncated agent_id; what matters is
    // that it changed — proving the render listener survived.
    expect(subjectEl.textContent).not.toBe(before);
  });
});

describe("mountConversation — group poll lifecycle across panel visibility", () => {
  it("starts the poll when entering a group with the panel visible", async () => {
    handle = mountConversation(host, store, noopHandlers);
    store.setPanelVisible(true);
    store.loadGroups([{ group_id: "g1", name: "Demo" }]);
    store.setActive({ kind: "group", groupId: "g1" });

    expect(groupHistoryMock).toHaveBeenCalledWith("g1");
  });

  it("stops the poll on hide and re-starts it on show without remounting", async () => {
    handle = mountConversation(host, store, noopHandlers);
    store.setPanelVisible(true);
    store.loadGroups([{ group_id: "g2", name: "Demo" }]);
    store.setActive({ kind: "group", groupId: "g2" });
    vi.mocked(groupHistoryMock).mockClear();

    store.setPanelVisible(false);
    // While hidden, the polling interval must not fire even if we
    // advance the clock past GROUP_POLL_INTERVAL_MS (4 s).
    vi.advanceTimersByTime(10_000);
    expect(groupHistoryMock).not.toHaveBeenCalled();

    store.setPanelVisible(true);
    // Re-show must trigger one immediate refresh — the regression the
    // round-3 review caught: the old lastConv-gated code stayed silent
    // because the active group hadn't changed.
    expect(groupHistoryMock).toHaveBeenCalledWith("g2");
  });
});

describe("mountConversation — group→group poll redirect", () => {
  it("switches the poll to the new group when the active group changes while visible", () => {
    handle = mountConversation(host, store, noopHandlers);
    store.setPanelVisible(true);
    store.loadGroups([
      { group_id: "gA", name: "A" },
      { group_id: "gB", name: "B" },
    ]);

    // Enter A — initial refresh fires.
    store.setActive({ kind: "group", groupId: "gA" });
    expect(groupHistoryMock).toHaveBeenLastCalledWith("gA");

    // Switch to B — must redirect: an immediate refresh for B, and
    // the interval closure must now point at B. The pre-fix bug left
    // the timer non-null so the line-304 restart guard skipped and the
    // closure kept polling A.
    vi.mocked(groupHistoryMock).mockClear();
    store.setActive({ kind: "group", groupId: "gB" });
    expect(groupHistoryMock).toHaveBeenLastCalledWith("gB");

    // Advance the timer past the interval — next tick must be for B.
    vi.mocked(groupHistoryMock).mockClear();
    vi.advanceTimersByTime(5_000);
    expect(groupHistoryMock).toHaveBeenLastCalledWith("gB");
    expect(groupHistoryMock).not.toHaveBeenCalledWith("gA");
  });
});

describe("mountConversation — hidden-time conv change still fires conv-change handlers on reopen", () => {
  it("DM warmup runs on reopen when the active DM changed while panel was hidden", async () => {
    // Track dmConnect calls — it's the canonical conv-change side effect.
    const apiModule = await import("./api");
    vi.mocked(apiModule.dmConnect).mockClear();

    handle = mountConversation(host, store, noopHandlers);
    store.setPanelVisible(true);
    const peerA = "a".repeat(64);
    const peerB = "b".repeat(64);
    store.ensureDm(peerA);
    store.ensureDm(peerB);
    store.setActive({ kind: "dm", peer: peerA });
    // Initial entry into peerA fires dmConnect once.
    expect(apiModule.dmConnect).toHaveBeenCalledWith(peerA);
    vi.mocked(apiModule.dmConnect).mockClear();

    // Hide, then pivot to peerB while hidden (the sidebar / restored
    // state can call setActive from outside panel.open()/close()).
    store.setPanelVisible(false);
    store.setActive({ kind: "dm", peer: peerB });

    // Reopen — dmConnect MUST fire for peerB. The hidden branch
    // previously updated lastConv = conv, so the visible-branch
    // conv-change gate saw lastConv === conv and skipped the warmup.
    store.setPanelVisible(true);
    expect(apiModule.dmConnect).toHaveBeenCalledWith(peerB);
  });
});

describe("mountConversation — reopen with no new messages reuses DOM (no animation flicker)", () => {
  it("does NOT call stream.replaceChildren on visibility flip when content is unchanged", () => {
    // Bob's P1#B: the previous assertion compared Node identity
    // before/after, but `replaceChildren(...ordered)` with keyed
    // reuse preserves Node refs through detach+reattach — Node
    // identity is unchanged, but the detach is what restarts
    // chat-bubble-pop. Spy directly on `replaceChildren` so the
    // mutation "lastStreamKey=null on visibility flip" gets caught
    // by the suite.
    handle = mountConversation(host, store, noopHandlers);
    store.setPanelVisible(true);
    const peer = "b".repeat(64);
    store.ensureDm(peer);
    store.setActive({ kind: "dm", peer });
    store.recordDirectMessage({
      from: peer,
      to: store.myId() ?? "",
      body: "hello",
      message_id: "m1",
      timestamp_ms: 1,
    });
    const stream = host.querySelector(".chat-stream") as HTMLElement;
    expect(stream.children.length).toBeGreaterThan(0);
    // Spy AFTER initial mount + render so we only observe the
    // hide/show cycle.
    const spy = vi.spyOn(stream, "replaceChildren");

    store.setPanelVisible(false);
    store.setPanelVisible(true);

    expect(spy).not.toHaveBeenCalled();
  });
});

describe("mountConversation — pendingScrollForKey is conv-scoped", () => {
  it("does NOT apply a deferred scroll-to-bottom from a different conv on reopen", () => {
    // Round-5 P2 / Bob's NOTE: pendingScroll set for DM-B during a
    // hidden-time pivot must not fire when reopening on DM-A whose
    // content is unchanged.
    handle = mountConversation(host, store, noopHandlers);
    store.setPanelVisible(true);
    const peerA = "a".repeat(63) + "1";
    const peerB = "b".repeat(63) + "2";
    store.ensureDm(peerA);
    store.ensureDm(peerB);
    store.setActive({ kind: "dm", peer: peerA });

    const stream = host.querySelector(".chat-stream") as HTMLElement;
    let scrollHeightValue = 0;
    Object.defineProperty(stream, "scrollHeight", {
      configurable: true,
      get: () => scrollHeightValue,
    });
    stream.scrollTop = 42; // a "user scrolled up" baseline

    store.setPanelVisible(false);
    scrollHeightValue = 1000;
    // Message lands for DM-B (active is still A — the message has
    // from=peerB, to=me, so it's recorded into the DM with peerB).
    // The hidden render sees conv=A unchanged, so pendingScrollForKey
    // would not even be set in this path. Force the divergent state
    // by setActive(B) while hidden, which makes the hidden render
    // tag pendingScrollForKey="dm:peerB".
    store.setActive({ kind: "dm", peer: peerB });
    // Pivot back to A while still hidden. A's content is unchanged
    // since the last visible render, so pendingScrollForKey stays
    // tagged for B.
    store.setActive({ kind: "dm", peer: peerA });

    // Reopen on A.
    store.setPanelVisible(true);

    // A's content was unchanged → the else-if path checks
    // `pendingScrollForKey === convKey(A)`. Pending is for B; the
    // anchor must NOT fire.
    expect(stream.scrollTop).toBe(42);
  });
});

describe("mountConversation — else-if anchor write is gated by justBecameVisible", () => {
  it("does NOT re-anchor scroll on a subsequent visible store-emit", () => {
    // Round-5 test-fidelity gap: a future mutation that drops the
    // `justBecameVisible &&` guard on the else-if scroll path would
    // cause every visible emit-with-pendingForThisConv to keep
    // yanking the user. This test pins the once-per-flip behaviour.
    handle = mountConversation(host, store, noopHandlers);
    store.setPanelVisible(true);
    const peer = "c".repeat(64);
    store.ensureDm(peer);
    store.setActive({ kind: "dm", peer });

    const stream = host.querySelector(".chat-stream") as HTMLElement;
    let scrollHeightValue = 0;
    Object.defineProperty(stream, "scrollHeight", {
      configurable: true,
      get: () => scrollHeightValue,
    });

    // Hide, new content while hidden, reopen — first visible render
    // applies the deferred anchor (clears pendingScrollForKey).
    store.setPanelVisible(false);
    scrollHeightValue = 500;
    store.recordDirectMessage({
      from: peer,
      to: store.myId() ?? "",
      body: "anchor me",
      message_id: "c1",
      timestamp_ms: 1,
    });
    store.setPanelVisible(true);
    expect(stream.scrollTop).toBe(500);

    // Now the user scrolls up (simulate via direct assignment) and
    // an UNRELATED store emit fires — e.g. a presence change or
    // unread-count tick. The else-if anchor must NOT fire again.
    stream.scrollTop = 100;
    scrollHeightValue = 500;
    store.tickPresence(); // fires emit() without changing conv.messages

    expect(stream.scrollTop).toBe(100);
  });
});

describe("mountConversation — scroll anchor across hide / show", () => {
  it("defers the scroll-to-bottom write while hidden and applies it on reopen", () => {
    handle = mountConversation(host, store, noopHandlers);
    store.setPanelVisible(true);
    const peer = "b".repeat(64);
    store.ensureDm(peer);
    store.setActive({ kind: "dm", peer });

    const stream = host.querySelector(".chat-stream") as HTMLElement;
    // jsdom doesn't populate scrollHeight from real layout, so stub it
    // to exercise the anchor logic. Both branches (hidden and visible)
    // read the same property; the test asserts that the hidden branch
    // doesn't write, and the visible branch does.
    let scrollHeightValue = 0;
    Object.defineProperty(stream, "scrollHeight", {
      configurable: true,
      get: () => scrollHeightValue,
    });

    // Hide the panel.
    store.setPanelVisible(false);
    // A new inbound DM lands while hidden.
    scrollHeightValue = 1234;
    store.recordDirectMessage({
      from: peer,
      to: store.myId() ?? "",
      body: "hello while hidden",
      message_id: "m1",
      timestamp_ms: Date.now(),
    });
    // Anchor must NOT have been written yet — `pendingScrollToBottom`
    // is the deferred-write flag. scrollTop on the synthesised stream
    // stays at its default 0; we assert via no replaceChildren / no
    // scrollTop assignment to a nonzero value while hidden by reading
    // scrollTop.
    expect(stream.scrollTop).toBe(0);

    // Reopen the panel. The render loop must now run the full diff
    // against real layout and apply the deferred scroll-to-bottom.
    store.setPanelVisible(true);
    expect(stream.scrollTop).toBe(scrollHeightValue);
  });
});
