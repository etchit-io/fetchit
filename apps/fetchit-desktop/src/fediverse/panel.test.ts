import { describe, expect, it, vi } from "vitest";
import { mountFediversePanel } from "./panel";
import type { PublicPostDelivery } from "./feedPost";

const post: PublicPostDelivery = {
  verifiedActorUrl: "https://m.example/users/a",
  activityJson: JSON.stringify({ type: "Note", id: "x", content: "hello feed" }),
};

describe("mountFediversePanel", () => {
  it("builds a header with the fediverse icon and a title, hidden by default", () => {
    const host = document.createElement("div");
    const api = mountFediversePanel(host, { onClose: () => undefined });
    expect(host.querySelector(".fediverse-panel__header")).not.toBeNull();
    expect(host.querySelector(".fediverse-panel__icon")).not.toBeNull();
    expect(host.querySelector(".fediverse-panel__title")?.textContent).toMatch(/feed|fediverse/i);
    expect(api.isOpen()).toBe(false);
    expect(host.hidden).toBe(true);
  });

  it("open/close/toggle flips visibility and close fires onClose", () => {
    const host = document.createElement("div");
    const onClose = vi.fn();
    const api = mountFediversePanel(host, { onClose });
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
    const api = mountFediversePanel(host, { onClose: () => undefined });
    expect(host.querySelectorAll(".feed-post").length).toBe(0);
    api.add(post);
    expect(host.querySelectorAll(".feed-post").length).toBe(1);
    expect(host.querySelector(".feed-post__body")?.textContent).toContain("hello feed");
  });

  it("the close button triggers onClose", () => {
    const host = document.createElement("div");
    const onClose = vi.fn();
    mountFediversePanel(host, { onClose });
    host.querySelector<HTMLButtonElement>(".fediverse-panel__close")?.click();
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
