import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ChatStore } from "./state";
import { mountSidebar, type SidebarHandlers } from "./sidebar";

const ME = "a".repeat(64);
const PEER_A = "b".repeat(64);
const PEER_B = "c".repeat(64);
const PEER_C = "d".repeat(64);

let host: HTMLElement;

beforeEach(() => {
  localStorage.clear();
  host = document.createElement("div");
  document.body.appendChild(host);
});

afterEach(() => {
  host.remove();
});

function makeStore(): ChatStore {
  const s = new ChatStore();
  s.setIdentity({ agent_id: ME, machine_id: "m" });
  return s;
}

function noopHandlers(): SidebarHandlers {
  return {
    onSelect: vi.fn(),
    onNewContact: vi.fn(),
    onNewGroup: vi.fn(),
    onJoinGroup: vi.fn(),
  };
}

describe("mountSidebar — empty state", () => {
  it("renders the 'No conversations yet' placeholder when the store has no convs", () => {
    const store = makeStore();
    mountSidebar(host, store, noopHandlers());
    const empty = host.querySelector(".chat-conv-empty");
    expect(empty).not.toBeNull();
    expect(empty?.textContent).toContain("No conversations yet");
    expect(host.querySelectorAll(".chat-conv").length).toBe(0);
  });
});

describe("mountSidebar — conversation list", () => {
  it("sorts conversations by lastActivityMs descending", () => {
    const store = makeStore();
    store.recordDirectMessage({
      from: PEER_A, to: ME, body: "old", timestamp_ms: 100, message_id: "1",
    });
    store.recordDirectMessage({
      from: PEER_B, to: ME, body: "newest", timestamp_ms: 300, message_id: "2",
    });
    store.recordDirectMessage({
      from: PEER_C, to: ME, body: "middle", timestamp_ms: 200, message_id: "3",
    });
    mountSidebar(host, store, noopHandlers());

    const rows = host.querySelectorAll<HTMLElement>(".chat-conv");
    expect(rows).toHaveLength(3);
    const titles = [...rows].map(
      (r) => r.querySelector(".chat-conv__title")?.textContent,
    );
    // Title falls back to `${peer.slice(0,8)}…` when no contact label exists.
    expect(titles[0]).toBe(`${PEER_B.slice(0, 8)}…`);
    expect(titles[1]).toBe(`${PEER_C.slice(0, 8)}…`);
    expect(titles[2]).toBe(`${PEER_A.slice(0, 8)}…`);
  });

  it("marks the active conversation with chat-conv--active and only that one", () => {
    const store = makeStore();
    store.recordDirectMessage({
      from: PEER_A, to: ME, body: "a", timestamp_ms: 1, message_id: "1",
    });
    store.recordDirectMessage({
      from: PEER_B, to: ME, body: "b", timestamp_ms: 2, message_id: "2",
    });
    store.setActive({ kind: "dm", peer: PEER_A });
    mountSidebar(host, store, noopHandlers());

    const actives = host.querySelectorAll(".chat-conv--active");
    expect(actives).toHaveLength(1);
    const activeTitle = actives[0].querySelector(".chat-conv__title")?.textContent;
    expect(activeTitle).toBe(`${PEER_A.slice(0, 8)}…`);
  });
});

describe("mountSidebar — selection", () => {
  it("clicking a row fires onSelect with the matching conversation", () => {
    const store = makeStore();
    store.recordDirectMessage({
      from: PEER_A, to: ME, body: "a", timestamp_ms: 1, message_id: "1",
    });
    store.recordDirectMessage({
      from: PEER_B, to: ME, body: "b", timestamp_ms: 2, message_id: "2",
    });
    const handlers = noopHandlers();
    mountSidebar(host, store, handlers);

    const rows = host.querySelectorAll<HTMLElement>(".chat-conv");
    // Row 1 is PEER_A (older), row 0 is PEER_B (newer).
    rows[1].click();
    expect(handlers.onSelect).toHaveBeenCalledTimes(1);
    const conv = (handlers.onSelect as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(conv.key).toEqual({ kind: "dm", peer: PEER_A });
  });

  it("Enter and Space on a focused row also fire onSelect", () => {
    const store = makeStore();
    store.recordDirectMessage({
      from: PEER_A, to: ME, body: "a", timestamp_ms: 1, message_id: "1",
    });
    const handlers = noopHandlers();
    mountSidebar(host, store, handlers);

    const row = host.querySelector<HTMLElement>(".chat-conv")!;
    row.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    row.dispatchEvent(new KeyboardEvent("keydown", { key: " ", bubbles: true }));
    expect(handlers.onSelect).toHaveBeenCalledTimes(2);
    const calls = (handlers.onSelect as ReturnType<typeof vi.fn>).mock.calls;
    expect(calls[0][0].key).toEqual({ kind: "dm", peer: PEER_A });
    expect(calls[1][0].key).toEqual({ kind: "dm", peer: PEER_A });
  });
});

describe("mountSidebar — presence dot", () => {
  it("DM avatar gets --online when peer relay presence is true", () => {
    const store = makeStore();
    store.recordDirectMessage({
      from: PEER_A, to: ME, body: "hi", timestamp_ms: 1, message_id: "1",
    });
    store.setRelayPresence(PEER_A, true);
    mountSidebar(host, store, noopHandlers());

    const avatar = host.querySelector(".chat-conv__avatar");
    expect(avatar?.classList.contains("chat-conv__avatar--online")).toBe(true);
  });

  it("avatar drops the --online modifier when peer is offline", () => {
    const store = makeStore();
    store.recordDirectMessage({
      from: PEER_A, to: ME, body: "hi", timestamp_ms: 1, message_id: "1",
    });
    store.setRelayPresence(PEER_A, false);
    mountSidebar(host, store, noopHandlers());

    const avatar = host.querySelector(".chat-conv__avatar");
    expect(avatar?.classList.contains("chat-conv__avatar--online")).toBe(false);
  });
});

describe("mountSidebar — unread badge", () => {
  it("renders the numeric badge when unread > 0", () => {
    const store = makeStore();
    // Panel closed + no active conv => inbound bumps unread.
    for (let i = 0; i < 5; i += 1) {
      store.recordDirectMessage({
        from: PEER_A, to: ME, body: `m${i}`, timestamp_ms: i + 1, message_id: `m${i}`,
      });
    }
    mountSidebar(host, store, noopHandlers());

    const badge = host.querySelector(".chat-conv__unread");
    expect(badge?.textContent).toBe("5");
  });

  it("caps the badge at 99+ for unread > 99", () => {
    const store = makeStore();
    for (let i = 0; i < 150; i += 1) {
      store.recordDirectMessage({
        from: PEER_A, to: ME, body: `m${i}`, timestamp_ms: i + 1, message_id: `m${i}`,
      });
    }
    mountSidebar(host, store, noopHandlers());

    const badge = host.querySelector(".chat-conv__unread");
    expect(badge?.textContent).toBe("99+");
  });

  it("omits the badge entirely when unread is 0", () => {
    const store = makeStore();
    store.setPanelVisible(true);
    store.setActive({ kind: "dm", peer: PEER_A });
    store.recordDirectMessage({
      from: PEER_A, to: ME, body: "hi", timestamp_ms: 1, message_id: "1",
    });
    mountSidebar(host, store, noopHandlers());

    expect(host.querySelector(".chat-conv__unread")).toBeNull();
  });
});

describe("mountSidebar — Nearby section", () => {
  it("is hidden when no nearby peers are reported", () => {
    const store = makeStore();
    mountSidebar(host, store, noopHandlers());
    const section = host.querySelector<HTMLElement>(".chat-nearby");
    expect(section).not.toBeNull();
    expect(section!.hidden).toBe(true);
    expect(section!.querySelector(".chat-nearby__heading")).toBeNull();
  });

  it("becomes visible with a heading + one row per peer when LAN peers arrive", () => {
    const store = makeStore();
    mountSidebar(host, store, noopHandlers());
    store.setNearbyPeers([
      { agentId: PEER_A, ip: "10.0.0.2", port: 4001, lastSeenMsAgo: 100 },
      { agentId: PEER_B, ip: "10.0.0.3", port: 4002, lastSeenMsAgo: 200 },
    ]);

    const section = host.querySelector<HTMLElement>(".chat-nearby")!;
    expect(section.hidden).toBe(false);
    expect(section.querySelector(".chat-nearby__heading")?.textContent).toBe("Nearby");
    const rows = section.querySelectorAll(".chat-nearby__row");
    expect(rows).toHaveLength(2);
    const metas = [...rows].map((r) => r.querySelector(".chat-nearby__meta")?.textContent);
    expect(metas).toContain("10.0.0.2:4001");
    expect(metas).toContain("10.0.0.3:4002");
  });
});

describe("mountSidebar — Nearby Add affordance", () => {
  it("clicking Add on a nearby peer row fires onNewContact", () => {
    const store = makeStore();
    const handlers = noopHandlers();
    mountSidebar(host, store, handlers);
    store.setNearbyPeers([
      { agentId: PEER_A, ip: "10.0.0.2", port: 4001, lastSeenMsAgo: 100 },
    ]);

    const addBtn = host.querySelector<HTMLButtonElement>(".chat-nearby__add")!;
    addBtn.click();
    expect(handlers.onNewContact).toHaveBeenCalledTimes(1);
  });
});

describe("mountSidebar — reactive re-render", () => {
  it("re-renders when the store mutates after mount", () => {
    const store = makeStore();
    mountSidebar(host, store, noopHandlers());
    expect(host.querySelector(".chat-conv-empty")).not.toBeNull();

    store.recordDirectMessage({
      from: PEER_A, to: ME, body: "hi", timestamp_ms: 1, message_id: "1",
    });
    expect(host.querySelector(".chat-conv-empty")).toBeNull();
    expect(host.querySelectorAll(".chat-conv")).toHaveLength(1);

    // Presence flip should reflect on the next render too.
    store.setRelayPresence(PEER_A, true);
    expect(
      host.querySelector(".chat-conv__avatar")?.classList.contains(
        "chat-conv__avatar--online",
      ),
    ).toBe(true);
  });
});

describe("mountSidebar — dispose", () => {
  it("stops re-rendering after dispose() is called", () => {
    const store = makeStore();
    const { dispose } = mountSidebar(host, store, noopHandlers());
    dispose();

    store.recordDirectMessage({
      from: PEER_A, to: ME, body: "after dispose", timestamp_ms: 1, message_id: "1",
    });
    // No re-render happened, so the empty-state node is still in place.
    expect(host.querySelector(".chat-conv-empty")).not.toBeNull();
    expect(host.querySelectorAll(".chat-conv")).toHaveLength(0);
  });
});
