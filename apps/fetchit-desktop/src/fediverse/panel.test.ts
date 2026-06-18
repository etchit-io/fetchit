import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

// eslint-disable-next-line import/first
import { invoke } from "@tauri-apps/api/core";
// eslint-disable-next-line import/first
import { resetConfirmForTests } from "./compose";
// eslint-disable-next-line import/first
import { mountFediversePanel } from "./panel";
// eslint-disable-next-line import/first
import type { PublicPostDelivery } from "./feedPost";

type InvokeMock = ReturnType<typeof vi.fn>;

const post: PublicPostDelivery = {
  verifiedActorUrl: "https://m.example/users/a",
  activityJson: JSON.stringify({ type: "Note", id: "x", content: "hello feed" }),
};

beforeEach(() => {
  (invoke as InvokeMock).mockReset();
  // The embedded compose surface queries actor status at mount; null
  // renders the mint view, which is fine for the pane-level tests.
  (invoke as InvokeMock).mockResolvedValue(null);
  resetConfirmForTests();
  document.body.innerHTML = "";
});

describe("mountFediversePanel", () => {
  it("builds a header with the fediverse icon and a title, hidden by default", () => {
    const host = document.createElement("div");
    const api = mountFediversePanel(host, { onClose: () => undefined, onOpenDm: () => undefined, onViewProfile: () => undefined, onAutonomi: () => undefined });
    expect(host.querySelector(".fediverse-panel__header")).not.toBeNull();
    expect(host.querySelector(".fediverse-panel__icon")).not.toBeNull();
    expect(host.querySelector(".fediverse-panel__title")?.textContent).toMatch(/feed|fediverse/i);
    expect(api.isOpen()).toBe(false);
    expect(host.hidden).toBe(true);
  });

  it("mounts the lookup section between header and feed body", () => {
    const host = document.createElement("div");
    mountFediversePanel(host, { onClose: () => undefined, onOpenDm: () => undefined, onViewProfile: () => undefined, onAutonomi: () => undefined });
    const children = Array.from(host.children);
    const headerIdx = children.findIndex((c) => c.classList.contains("fediverse-panel__header"));
    const lookupIdx = children.findIndex((c) => c.classList.contains("fediverse-lookup"));
    // mountFeed owns the body element's class ("feed").
    const bodyIdx = children.findIndex((c) => c.classList.contains("feed"));
    expect(lookupIdx).toBeGreaterThan(headerIdx);
    expect(lookupIdx).toBeLessThan(bodyIdx);
    expect(host.querySelector(".fediverse-lookup__input")).not.toBeNull();
  });

  it("open/close/toggle flips visibility and close fires onClose", () => {
    const host = document.createElement("div");
    const onClose = vi.fn();
    const api = mountFediversePanel(host, { onClose, onOpenDm: () => undefined, onViewProfile: () => undefined, onAutonomi: () => undefined });
    api.open();
    expect(api.isOpen()).toBe(true);
    api.close();
    expect(api.isOpen()).toBe(false);
    expect(onClose).toHaveBeenCalledTimes(1);
    api.toggle();
    expect(api.isOpen()).toBe(true);
  });

  it("add() pushes a post into the feed", () => {
    const host = document.createElement("div");
    const api = mountFediversePanel(host, { onClose: () => undefined, onOpenDm: () => undefined, onViewProfile: () => undefined, onAutonomi: () => undefined });
    expect(host.querySelectorAll(".feed-post").length).toBe(0);
    api.add(post);
    expect(host.querySelectorAll(".feed-post").length).toBe(1);
    expect(host.querySelector(".feed-post__body")?.textContent).toContain("hello feed");
  });

  it("the close button triggers onClose", () => {
    const host = document.createElement("div");
    const onClose = vi.fn();
    mountFediversePanel(host, { onClose, onOpenDm: () => undefined, onViewProfile: () => undefined, onAutonomi: () => undefined });
    host.querySelector<HTMLButtonElement>(".fediverse-panel__close")?.click();
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("mounts the compose surface under the feed", () => {
    const host = document.createElement("div");
    mountFediversePanel(host, { onClose: () => undefined, onOpenDm: () => undefined, onViewProfile: () => undefined, onAutonomi: () => undefined });
    expect(host.querySelector(".fediverse-compose")).not.toBeNull();
  });

  it("reply publicly on a card prefills compose with the VERIFIED actor", async () => {
    (invoke as InvokeMock).mockImplementation((cmd: string) =>
      cmd === "fediverse_actor_status" ? Promise.resolve("josh") : Promise.resolve(null),
    );
    const host = document.createElement("div");
    document.body.append(host);
    const api = mountFediversePanel(host, { onClose: () => undefined, onOpenDm: () => undefined, onViewProfile: () => undefined, onAutonomi: () => undefined });
    await vi.waitFor(() => {
      expect(host.querySelector(".fediverse-compose__textarea")).not.toBeNull();
    });
    api.add(post);
    host.querySelector<HTMLButtonElement>(".feed-post__reply")!.click();
    const chip = host.querySelector<HTMLElement>(".fediverse-compose__reply")!;
    expect(chip.hidden).toBe(false);
    expect(chip.textContent).toContain("https://m.example/users/a");
  });

  it("a feed post's autonomi:// address opens in the reader via onAutonomi", () => {
    const host = document.createElement("div");
    const onAutonomi = vi.fn();
    const api = mountFediversePanel(host, {
      onClose: () => undefined,
      onOpenDm: () => undefined,
      onViewProfile: () => undefined,
      onAutonomi,
    });
    const addr = "d".repeat(64);
    api.add({
      verifiedActorUrl: "https://m.example/users/a",
      activityJson: JSON.stringify({ type: "Note", id: "p1", content: `see autonomi://${addr}` }),
    });
    host.querySelector<HTMLButtonElement>(".chat-preview__btn--ghost")!.click();
    expect(onAutonomi).toHaveBeenCalledWith(`autonomi://${addr}`);
  });
});
