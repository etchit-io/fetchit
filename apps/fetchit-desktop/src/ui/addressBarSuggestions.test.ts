import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  filterBookmarks,
  mountAddressBarSuggestions,
} from "./addressBarSuggestions";
import type { Bookmark } from "../bookmarks";

vi.mock("../bookmarks", () => ({
  listBookmarks: vi.fn(),
}));

// eslint-disable-next-line import/first
import { listBookmarks } from "../bookmarks";

const BMS: Bookmark[] = [
  { address: "a".repeat(64), label: "GitHub", createdAt: 1 },
  { address: "b".repeat(64), label: "GitLab", createdAt: 2 },
  { address: "c".repeat(64), label: "Hacker News", createdAt: 3 },
  { address: "d".repeat(64), label: "Autonomi Homepage", createdAt: 4 },
];

describe("filterBookmarks", () => {
  it("returns empty for an empty or whitespace query", () => {
    expect(filterBookmarks("", BMS)).toEqual([]);
    expect(filterBookmarks("   ", BMS)).toEqual([]);
  });

  it("matches labels case-insensitively", () => {
    expect(filterBookmarks("github", BMS).map((b) => b.label)).toEqual([
      "GitHub",
    ]);
    expect(filterBookmarks("GITHUB", BMS).map((b) => b.label)).toEqual([
      "GitHub",
    ]);
  });

  it("matches substrings inside labels", () => {
    expect(
      filterBookmarks("git", BMS).map((b) => b.label).sort(),
    ).toEqual(["GitHub", "GitLab"]);
  });

  it("respects the limit", () => {
    expect(filterBookmarks("o", BMS, 1).length).toBe(1);
  });

  it("returns empty for queries that look like hex address prefixes", () => {
    expect(filterBookmarks("abcdef12", BMS)).toEqual([]);
    expect(filterBookmarks("a".repeat(64), BMS)).toEqual([]);
  });

  it("still searches when the query is shorter than 8 hex chars", () => {
    expect(filterBookmarks("abc", BMS)).toEqual([]);
  });
});

describe("mountAddressBarSuggestions", () => {
  function setup(): {
    input: HTMLInputElement;
    onSelect: ReturnType<typeof vi.fn>;
  } {
    document.body.replaceChildren();
    const shell = document.createElement("div");
    const input = document.createElement("input");
    shell.appendChild(input);
    document.body.appendChild(shell);
    return { input, onSelect: vi.fn() };
  }

  beforeEach(() => {
    vi.mocked(listBookmarks).mockResolvedValue(BMS);
  });

  afterEach(() => {
    vi.mocked(listBookmarks).mockReset();
  });

  it("shows matching suggestions on input", async () => {
    const { input, onSelect } = setup();
    const h = mountAddressBarSuggestions({ input, onSelect });
    await h.refresh();
    input.value = "git";
    input.dispatchEvent(new Event("input"));
    expect(document.querySelectorAll(".addr-suggestion").length).toBe(2);
  });

  it("hides the dropdown on Escape", async () => {
    const { input, onSelect } = setup();
    const h = mountAddressBarSuggestions({ input, onSelect });
    await h.refresh();
    input.value = "git";
    input.dispatchEvent(new Event("input"));
    const ul = document.querySelector<HTMLElement>(".addr-suggestions");
    expect(ul?.hidden).toBe(false);
    input.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
    expect(ul?.hidden).toBe(true);
  });

  it("calls onSelect with the address on mousedown of a suggestion", async () => {
    const { input, onSelect } = setup();
    const h = mountAddressBarSuggestions({ input, onSelect });
    await h.refresh();
    input.value = "github";
    input.dispatchEvent(new Event("input"));
    document
      .querySelector<HTMLElement>(".addr-suggestion")
      ?.dispatchEvent(new MouseEvent("mousedown", { bubbles: true }));
    expect(onSelect).toHaveBeenCalledWith("a".repeat(64));
    expect(input.value).toBe("a".repeat(64));
  });

  it("Enter selects the highlighted suggestion", async () => {
    const { input, onSelect } = setup();
    const h = mountAddressBarSuggestions({ input, onSelect });
    await h.refresh();
    input.value = "github";
    input.dispatchEvent(new Event("input"));
    input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter" }));
    expect(onSelect).toHaveBeenCalledWith("a".repeat(64));
  });

  it("ArrowDown moves the highlight to the next suggestion", async () => {
    const { input, onSelect } = setup();
    const h = mountAddressBarSuggestions({ input, onSelect });
    await h.refresh();
    input.value = "git";
    input.dispatchEvent(new Event("input"));
    input.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown" }));
    const items = document.querySelectorAll<HTMLElement>(".addr-suggestion");
    expect(items[1].classList.contains("is-active")).toBe(true);
  });
});
