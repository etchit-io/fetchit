import { describe, expect, it, vi } from "vitest";
import { renderBubble } from "./bubble";
import type { ChatBubble } from "./state";

const ME = "a".repeat(64);
const ADDR = "f".repeat(64);

function bubble(overrides: Partial<ChatBubble> = {}): ChatBubble {
  return {
    id: "b1",
    from: ME,
    body: "hello",
    timestampMs: Date.now(),
    mine: true,
    ...overrides,
  };
}

describe("renderBubble — content", () => {
  it("renders plain text as a single text node inside the bubble", () => {
    const handlers = { onAutonomi: vi.fn(), onCard: vi.fn(), onInvite: vi.fn() };
    const row = renderBubble(bubble({ body: "no urls here" }), handlers);
    const b = row.querySelector(".chat-bubble");
    expect(b?.textContent).toBe("no urls here");
    expect(row.querySelectorAll("a")).toHaveLength(0);
  });

  it("linkifies an autonomi:// address", () => {
    const handlers = { onAutonomi: vi.fn(), onCard: vi.fn(), onInvite: vi.fn() };
    const row = renderBubble(
      bubble({ body: `check autonomi://${ADDR} please` }),
      handlers,
    );
    const links = row.querySelectorAll("a.chat-link");
    expect(links).toHaveLength(1);
    expect(links[0].getAttribute("title")).toBe(`autonomi://${ADDR}`);
  });

  it("clicking an autonomi link fires onAutonomi with the full URI", () => {
    const handlers = { onAutonomi: vi.fn(), onCard: vi.fn(), onInvite: vi.fn() };
    const row = renderBubble(bubble({ body: `autonomi://${ADDR}` }), handlers);
    const a = row.querySelector("a.chat-link") as HTMLAnchorElement;
    a.click();
    expect(handlers.onAutonomi).toHaveBeenCalledWith(`autonomi://${ADDR}`);
  });

  it("routes x0x://invite/ to onInvite, x0x://agent/ to onCard", () => {
    const handlers = { onAutonomi: vi.fn(), onCard: vi.fn(), onInvite: vi.fn() };
    const row = renderBubble(
      bubble({ body: "x0x://invite/abc x0x://agent/xyz" }),
      handlers,
    );
    const links = row.querySelectorAll<HTMLAnchorElement>("a.chat-link");
    expect(links).toHaveLength(2);
    links[0].click();
    links[1].click();
    expect(handlers.onInvite).toHaveBeenCalledWith("x0x://invite/abc");
    expect(handlers.onCard).toHaveBeenCalledWith("x0x://agent/xyz");
  });

  it("preserves text around URIs", () => {
    const handlers = { onAutonomi: vi.fn(), onCard: vi.fn(), onInvite: vi.fn() };
    const row = renderBubble(
      bubble({ body: `look: autonomi://${ADDR} now!` }),
      handlers,
    );
    expect(row.textContent?.startsWith("look: ")).toBe(true);
    expect(row.textContent?.endsWith(" now!")).toBe(false); // timestamp gets appended
    expect(row.textContent).toContain(" now!");
  });
});

describe("renderBubble — direction", () => {
  it("uses chat-row--out for my own messages", () => {
    const handlers = { onAutonomi: vi.fn(), onCard: vi.fn(), onInvite: vi.fn() };
    const row = renderBubble(bubble({ mine: true }), handlers);
    expect(row.className).toContain("chat-row--out");
  });

  it("uses chat-row--in for incoming messages", () => {
    const handlers = { onAutonomi: vi.fn(), onCard: vi.fn(), onInvite: vi.fn() };
    const row = renderBubble(bubble({ mine: false }), handlers);
    expect(row.className).toContain("chat-row--in");
  });
});
