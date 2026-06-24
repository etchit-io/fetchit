import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: () => Promise.reject(new Error("no daemon")),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
}));

// vi.mock factories are hoisted to the top of the file; the spies they
// reference must be hoisted alongside via vi.hoisted() so they exist by
// the time the mock module is loaded.
const { conversationDispose, conversationStopPolling, mountConversationMock } =
  vi.hoisted(() => {
    const conversationDispose = vi.fn();
    const conversationStopPolling = vi.fn();
    const mountConversationMock = vi.fn(() => ({
      stopPolling: conversationStopPolling,
      dispose: conversationDispose,
    }));
    return {
      conversationDispose,
      conversationStopPolling,
      mountConversationMock,
    };
  });
vi.mock("./conversation", () => ({
  mountConversation: mountConversationMock,
}));

import { fillIdentityBadge, mountChatPanel } from "./panel";

describe("fillIdentityBadge", () => {
  it("shows the user's name and avatar, never the raw hex (rule 1)", () => {
    const badge = document.createElement("button");
    const agentId = "ab".repeat(32);
    fillIdentityBadge(badge, "Ada Lovelace", agentId);
    expect(badge.querySelector(".chat-panel__id-name")?.textContent).toBe(
      "Ada Lovelace",
    );
    expect(badge.querySelector(".chat-panel__id-avatar")?.textContent).toBe("A");
    // The 64-hex must not leak into the visible badge text.
    expect(badge.textContent).not.toContain(agentId.slice(0, 8));
  });

  it("derives the avatar hue deterministically from the agent id", () => {
    const badge = document.createElement("button");
    fillIdentityBadge(badge, "Bob", "07" + "11".repeat(31));
    expect(
      badge.querySelector(".chat-panel__id-avatar")?.classList.contains(
        "chat-avatar--g7",
      ),
    ).toBe(true);
  });

  it("restores the share affordance after a failure state", () => {
    const badge = document.createElement("button");
    badge.title = "Tap to retry";
    badge.textContent = "Chat unavailable";
    fillIdentityBadge(badge, "Ada", "cd".repeat(32));
    expect(badge.title).toBe("Share my code");
    expect(badge.getAttribute("aria-label")).toBe("Share my code");
    expect(badge.textContent).not.toContain("Chat unavailable");
  });
});

let host: HTMLElement;

beforeEach(() => {
  localStorage.clear();
  conversationDispose.mockClear();
  conversationStopPolling.mockClear();
  mountConversationMock.mockClear();
  host = document.createElement("section");
  document.body.appendChild(host);
});

afterEach(() => {
  host.remove();
  document.body.classList.remove("chat-docked");
});

describe("mountChatPanel — dock mode", () => {
  it("starts undocked by default", () => {
    const api = mountChatPanel(host, {
      onAutonomi: () => {},
      onClose: () => {},
      onOpenFullProfile: () => {},
    });
    expect(api.isDocked()).toBe(false);
    expect(host.classList.contains("chat-panel--docked")).toBe(false);
  });

  it("openDm opens the panel even when the daemon is down", async () => {
    const api = mountChatPanel(host, {
      onAutonomi: () => {},
      onClose: () => {},
      onOpenFullProfile: () => {},
    });
    expect(api.isOpen()).toBe(false);
    await api.openDm("a".repeat(64));
    expect(api.isOpen()).toBe(true);
  });

  it("setDocked(true) toggles the class and persists the preference", () => {
    const api = mountChatPanel(host, {
      onAutonomi: () => {},
      onClose: () => {},
      onOpenFullProfile: () => {},
    });
    api.setDocked(true);
    expect(api.isDocked()).toBe(true);
    expect(host.classList.contains("chat-panel--docked")).toBe(true);
    expect(localStorage.getItem("fetchit-chat:dock")).toBe("1");
  });

  it("re-mount with a persisted dock pref restores it", () => {
    localStorage.setItem("fetchit-chat:dock", "1");
    const api = mountChatPanel(host, {
      onAutonomi: () => {},
      onClose: () => {},
      onOpenFullProfile: () => {},
    });
    expect(api.isDocked()).toBe(true);
    expect(host.classList.contains("chat-panel--docked")).toBe(true);
  });

  it("body chat-docked class follows panel visibility", () => {
    const api = mountChatPanel(host, {
      onAutonomi: () => {},
      onClose: () => {},
      onOpenFullProfile: () => {},
    });
    api.setDocked(true);
    expect(document.body.classList.contains("chat-docked")).toBe(false);
    host.hidden = false;
    api.setDocked(true);
    expect(document.body.classList.contains("chat-docked")).toBe(true);
    api.close();
    expect(document.body.classList.contains("chat-docked")).toBe(false);
  });
});

describe("mountChatPanel — lifecycle cleanup", () => {
  it("close() stops the conversation poll but does NOT dispose the handle", () => {
    // The conversation pane is mounted ONCE for the lifetime of the
    // panel host. Calling dispose() on close would unsubscribe the
    // render listener permanently — re-open would then paint stale
    // DOM that no longer reacts to store events. close() must stop
    // the group-poll timer only.
    const api = mountChatPanel(host, {
      onAutonomi: () => {},
      onClose: () => {},
      onOpenFullProfile: () => {},
    });
    expect(conversationStopPolling).not.toHaveBeenCalled();
    expect(conversationDispose).not.toHaveBeenCalled();
    api.close();
    expect(conversationStopPolling).toHaveBeenCalledTimes(1);
    expect(conversationDispose).not.toHaveBeenCalled();
  });

  it("mountConversation is called once across open / close / open", async () => {
    // Repeated open/close cycles must not re-mount the conversation
    // pane. A re-mount would leak DOM and double-subscribe to the
    // store; a missing re-mount with a permanent dispose() would
    // leave the pane frozen on reopen. The single-mount invariant is
    // the property that lets us avoid both failure modes.
    const api = mountChatPanel(host, {
      onAutonomi: () => {},
      onClose: () => {},
      onOpenFullProfile: () => {},
    });
    expect(mountConversationMock).toHaveBeenCalledTimes(1);
    // open()/close() do not gate on whether the daemon is reachable;
    // bootstrap failures still hide/show the host without remounting
    // the conv pane. Awaiting open() catches both the success and
    // bootstrap-failed paths.
    await api.open();
    await api.toggle();
    await api.open();
    expect(mountConversationMock).toHaveBeenCalledTimes(1);
    expect(conversationDispose).not.toHaveBeenCalled();
  });
});
