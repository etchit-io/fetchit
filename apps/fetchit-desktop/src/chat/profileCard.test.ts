import { describe, it, expect, vi } from "vitest";
import { openProfileCard } from "./profileCard";
import type { ProfileOutcome } from "./types";

const PROFILE: ProfileOutcome = {
  kind: "profile",
  displayName: "Alice",
  bio: "hi there",
  website: "https://example.invalid/alice",
  links: [
    { kind: "etchit", label: "my page", addr: "ab".repeat(32) },
    { kind: "x0x", label: "dm me", addr: "cd".repeat(32) },
  ],
  avatar: null,
  issuedAtMs: 5,
};

function card(): HTMLElement | null {
  return document.querySelector(".chat-profile:not([hidden])");
}

describe("openProfileCard", () => {
  it("renders display name + bio + website + link chips from a loaded profile", async () => {
    openProfileCard({
      agentId: "aa".repeat(32),
      fetchProfile: () => Promise.resolve(PROFILE),
      fetchAvatar: () => Promise.resolve("data:image/webp;base64,AA=="),
      onAutonomi: vi.fn(),
      onMessage: vi.fn(),
      confirmOpen: vi.fn(),
      onOpenFullProfile: vi.fn(),
    });
    await vi.waitFor(() => expect(card()?.textContent).toContain("Alice"));
    expect(card()!.textContent).toContain("hi there");
    expect(card()!.querySelectorAll(".chat-profile__link").length).toBe(2);
  });

  it("shows the empty state when the contact has no profile", async () => {
    openProfileCard({
      agentId: "aa".repeat(32),
      fetchProfile: () => Promise.resolve({ kind: "none" }),
      fetchAvatar: () => Promise.resolve(""),
      onAutonomi: vi.fn(),
      onMessage: vi.fn(),
      confirmOpen: vi.fn(),
      onOpenFullProfile: vi.fn(),
    });
    await vi.waitFor(() => expect(card()?.textContent).toMatch(/hasn.t published/i));
  });

  it("shows an error line when the fetch rejects", async () => {
    openProfileCard({
      agentId: "aa".repeat(32),
      fetchProfile: () => Promise.reject(new Error("this profile failed verification")),
      fetchAvatar: () => Promise.resolve(""),
      onAutonomi: vi.fn(),
      onMessage: vi.fn(),
      confirmOpen: vi.fn(),
      onOpenFullProfile: vi.fn(),
    });
    await vi.waitFor(() => expect(card()?.textContent).toContain("failed verification"));
  });

  it("routes an etchit link to onAutonomi and closes", async () => {
    const onAutonomi = vi.fn();
    openProfileCard({
      agentId: "aa".repeat(32),
      fetchProfile: () => Promise.resolve(PROFILE),
      fetchAvatar: () => Promise.resolve(""),
      onAutonomi,
      onMessage: vi.fn(),
      confirmOpen: vi.fn(),
      onOpenFullProfile: vi.fn(),
    });
    await vi.waitFor(() => expect(card()).not.toBeNull());
    card()!.querySelector<HTMLElement>(".chat-profile__link")!.click();
    expect(onAutonomi).toHaveBeenCalledWith(`autonomi://${"ab".repeat(32)}`);
    expect(card()).toBeNull();
  });

  it("routes an x0x link to onMessage and closes", async () => {
    const onMessage = vi.fn();
    openProfileCard({
      agentId: "aa".repeat(32),
      fetchProfile: () => Promise.resolve(PROFILE),
      fetchAvatar: () => Promise.resolve(""),
      onAutonomi: vi.fn(),
      onMessage,
      confirmOpen: vi.fn(),
      onOpenFullProfile: vi.fn(),
    });
    await vi.waitFor(() => expect(card()).not.toBeNull());
    // The second chip is the x0x link ("dm me").
    card()!.querySelectorAll<HTMLElement>(".chat-profile__link")[1].click();
    expect(onMessage).toHaveBeenCalledWith("cd".repeat(32));
    expect(card()).toBeNull();
  });

  it("fires confirmOpen before opening the website (speed bump)", async () => {
    const confirmOpen = vi.fn();
    openProfileCard({
      agentId: "aa".repeat(32),
      fetchProfile: () => Promise.resolve(PROFILE),
      fetchAvatar: () => Promise.resolve(""),
      onAutonomi: vi.fn(),
      onMessage: vi.fn(),
      confirmOpen,
      onOpenFullProfile: vi.fn(),
    });
    await vi.waitFor(() => expect(card()).not.toBeNull());
    card()!.querySelector<HTMLElement>(".chat-profile__website")!.click();
    expect(confirmOpen).toHaveBeenCalledWith("https://example.invalid/alice");
  });

  it("lazily fetches and fills the avatar after the card mounts", async () => {
    const fetchAvatar = vi.fn().mockResolvedValue("data:image/webp;base64,QQ==");
    openProfileCard({
      agentId: "aa".repeat(32),
      fetchProfile: () =>
        Promise.resolve({
          ...PROFILE,
          avatar: { addr: "bb".repeat(32), mime: "image/webp", w: 64, h: 64, bytesLen: 100 },
        }),
      fetchAvatar,
      onAutonomi: vi.fn(),
      onMessage: vi.fn(),
      confirmOpen: vi.fn(),
      onOpenFullProfile: vi.fn(),
    });
    await vi.waitFor(() => expect(card()?.querySelector(".chat-profile__avatar img")).not.toBeNull());
    expect(fetchAvatar).toHaveBeenCalledWith("bb".repeat(32), "image/webp", 100);
  });
});
