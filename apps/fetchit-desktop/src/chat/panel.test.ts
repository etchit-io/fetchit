import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: () => Promise.reject(new Error("no daemon")),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
}));

import { mountChatPanel } from "./panel";

let host: HTMLElement;

beforeEach(() => {
  localStorage.clear();
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
    });
    expect(api.isDocked()).toBe(false);
    expect(host.classList.contains("chat-panel--docked")).toBe(false);
  });

  it("setDocked(true) toggles the class and persists the preference", () => {
    const api = mountChatPanel(host, {
      onAutonomi: () => {},
      onClose: () => {},
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
    });
    expect(api.isDocked()).toBe(true);
    expect(host.classList.contains("chat-panel--docked")).toBe(true);
  });

  it("body chat-docked class follows panel visibility", () => {
    const api = mountChatPanel(host, {
      onAutonomi: () => {},
      onClose: () => {},
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
