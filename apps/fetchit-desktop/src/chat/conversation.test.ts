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

describe("mountConversation — scroll anchor across hide / show", () => {
  it("defers the scroll-to-bottom write while hidden and applies it on reopen", () => {
    handle = mountConversation(host, store, noopHandlers);
    store.setPanelVisible(true);
    const peer = "b".repeat(64);
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
