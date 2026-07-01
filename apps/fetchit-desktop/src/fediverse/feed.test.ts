import { describe, expect, it } from "vitest";
import { mountFeed } from "./feed";
import type { PublicPostDelivery } from "./feedPost";

function post(id: string, content = "hi"): PublicPostDelivery {
  return {
    verifiedActorUrl: "https://m.example/users/a",
    activityJson: JSON.stringify({
      type: "Create",
      id,
      object: { type: "Note", content },
    }),
  };
}

describe("mountFeed", () => {
  it("shows an empty state until a post arrives", () => {
    const host = document.createElement("div");
    const feed = mountFeed(host);
    const empty = host.querySelector<HTMLElement>(".feed__empty");
    expect(empty).not.toBeNull();
    expect(empty?.hidden).toBe(false);
    feed.add(post("a"));
    expect(empty?.hidden).toBe(true);
  });

  it("renders newest first", () => {
    const host = document.createElement("div");
    const feed = mountFeed(host);
    feed.add(post("first", "FIRST"));
    feed.add(post("second", "SECOND"));
    const cards = host.querySelectorAll(".feed-post");
    expect(cards.length).toBe(2);
    expect(cards[0].textContent).toContain("SECOND");
  });

  it("dedupes posts with the same activity id", () => {
    const host = document.createElement("div");
    const feed = mountFeed(host);
    feed.add(post("dup"));
    feed.add(post("dup"));
    expect(host.querySelectorAll(".feed-post").length).toBe(1);
    expect(feed.count()).toBe(1);
  });

  it("clear() empties the feed and restores the empty state", () => {
    const host = document.createElement("div");
    const feed = mountFeed(host);
    feed.add(post("a"));
    feed.clear();
    expect(host.querySelectorAll(".feed-post").length).toBe(0);
    expect(host.querySelector<HTMLElement>(".feed__empty")?.hidden).toBe(false);
  });
});
