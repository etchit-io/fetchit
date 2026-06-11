import { describe, expect, it, vi } from "vitest";
import { bubbleRenderKey, renderBubble, type BubbleHandlers } from "./bubble";
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

function makeHandlers(): BubbleHandlers {
  return {
    onAutonomi: vi.fn(),
    onCard: vi.fn(),
    onInvite: vi.fn(),
    onProfile: vi.fn(),
  };
}

describe("renderBubble — content", () => {
  it("renders plain text as a single text node inside the bubble", () => {
    const handlers = makeHandlers();
    const row = renderBubble(bubble({ body: "no urls here" }), handlers);
    const b = row.querySelector(".chat-bubble");
    expect(b?.textContent).toBe("no urls here");
    expect(row.querySelectorAll("a")).toHaveLength(0);
  });

  it("strips autonomi:// URLs from the text bubble (preview card represents them)", () => {
    const handlers = makeHandlers();
    const row = renderBubble(
      bubble({ body: `check autonomi://${ADDR} please` }),
      handlers,
    );
    const inlineLinks = row.querySelectorAll("a.chat-link");
    expect(inlineLinks).toHaveLength(0);
    const previews = row.querySelectorAll(".chat-preview");
    expect(previews).toHaveLength(1);
    // Surrounding text is preserved in the text bubble.
    const textBubble = row.querySelector(".chat-bubble");
    expect(textBubble?.textContent).toContain("check");
    expect(textBubble?.textContent).toContain("please");
  });

  it("for an autonomi-only body, hides the text bubble entirely", () => {
    const handlers = makeHandlers();
    const row = renderBubble(bubble({ body: `autonomi://${ADDR}` }), handlers);
    expect(row.querySelector(".chat-bubble")).toBeNull();
    expect(row.querySelectorAll(".chat-preview")).toHaveLength(1);
  });

  it("clicking the preview card's Open button fires onAutonomi", () => {
    const handlers = makeHandlers();
    const row = renderBubble(bubble({ body: `autonomi://${ADDR}` }), handlers);
    const openBtn = row.querySelectorAll<HTMLButtonElement>(
      ".chat-preview__btn",
    )[1];
    openBtn.click();
    expect(handlers.onAutonomi).toHaveBeenCalledWith(`autonomi://${ADDR}`);
  });

  it("routes x0x://invite/ to onInvite, x0x://agent/ to onCard", () => {
    const handlers = makeHandlers();
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

  it("paints an 'unverified sender' badge under inbound bubbles where verified===false", () => {
    const handlers = makeHandlers();
    const row = renderBubble(
      bubble({ mine: false, body: "hi", verified: false }),
      handlers,
    );
    const badge = row.querySelector(".chat-bubble__unverified");
    expect(badge).not.toBeNull();
    expect(badge?.textContent).toContain("unverified");
  });

  it("does NOT paint the unverified badge on outbound bubbles even with verified===false", () => {
    const handlers = makeHandlers();
    const row = renderBubble(
      bubble({ mine: true, body: "hi", verified: false }),
      handlers,
    );
    expect(row.querySelector(".chat-bubble__unverified")).toBeNull();
  });

  it("does NOT paint the unverified badge when verified===true (TransitEnvelope path)", () => {
    const handlers = makeHandlers();
    const row = renderBubble(
      bubble({ mine: false, body: "hi", verified: true }),
      handlers,
    );
    expect(row.querySelector(".chat-bubble__unverified")).toBeNull();
  });

  it("does NOT paint the unverified badge when verified is undefined (outbound default)", () => {
    const handlers = makeHandlers();
    const row = renderBubble(bubble({ mine: false, body: "hi" }), handlers);
    expect(row.querySelector(".chat-bubble__unverified")).toBeNull();
  });

  it("bubbleRenderKey changes when verified flips so the keyed-diff repaints", () => {
    const a = bubbleRenderKey(bubble({ id: "m1", verified: undefined }));
    const b = bubbleRenderKey(bubble({ id: "m1", verified: true }));
    const c = bubbleRenderKey(bubble({ id: "m1", verified: false }));
    expect(a).not.toBe(b);
    expect(b).not.toBe(c);
  });

  it("routes fetchit://share/v3/ to onProfile", () => {
    const handlers = makeHandlers();
    const v3
      = "fetchit://share/v3/"
        + "aa".repeat(32)
        + "/"
        + "bb".repeat(32)
        + "?relay=https://relay.example/";
    const row = renderBubble(bubble({ body: `look at this ${v3}` }), handlers);
    const links = row.querySelectorAll<HTMLAnchorElement>("a.chat-link");
    expect(links).toHaveLength(1);
    links[0].click();
    expect(handlers.onProfile).toHaveBeenCalledWith(v3);
    expect(handlers.onCard).not.toHaveBeenCalled();
    expect(handlers.onInvite).not.toHaveBeenCalled();
  });

  it("preserves text around URIs", () => {
    const handlers = makeHandlers();
    const row = renderBubble(
      bubble({ body: `look: autonomi://${ADDR} now!` }),
      handlers,
    );
    const textBubble = row.querySelector(".chat-bubble");
    expect(textBubble?.textContent).toContain("look: ");
    expect(textBubble?.textContent).toContain(" now!");
  });

  it("keeps the text bubble visible for an autonomi-only message that's still sending (mine)", () => {
    const handlers = makeHandlers();
    const row = renderBubble(
      bubble({ body: `autonomi://${ADDR}`, mine: true, status: "sending" }),
      handlers,
    );
    expect(row.querySelector(".chat-bubble")).not.toBeNull();
  });
});

describe("renderBubble — outbound status", () => {
  it("shows a Sending… caption while the bubble is in flight", () => {
    const handlers = makeHandlers();
    const row = renderBubble(
      bubble({ mine: true, status: "sending" }),
      handlers,
    );
    const cap = row.querySelector(".chat-bubble__substatus--sending");
    expect(cap?.textContent).toBe("Sending…");
  });

  it("shows an explicit 'Not delivered' caption when the send failed", () => {
    const handlers = makeHandlers();
    const row = renderBubble(
      bubble({ mine: true, status: "failed", failureReason: "timeout" }),
      handlers,
    );
    const cap = row.querySelector<HTMLElement>(
      ".chat-bubble__substatus--failed",
    );
    expect(cap?.textContent).toBe("Not delivered");
    expect(cap?.title).toBe("timeout");
  });

  it("shows ⏳ + Sending caption while in flight", () => {
    const handlers = makeHandlers();
    const sending = renderBubble(
      bubble({ mine: true, status: "sending" }),
      handlers,
    );
    expect(
      sending.querySelector(".chat-bubble__status--sending")?.textContent,
    ).toBe("⏳");
    expect(
      sending.querySelector(".chat-bubble__substatus--sending")?.textContent,
    ).toBe("Sending…");
  });

  it("shows ✓ for delivered with no substatus caption", () => {
    const handlers = makeHandlers();
    const delivered = renderBubble(
      bubble({ mine: true, status: "delivered" }),
      handlers,
    );
    expect(
      delivered.querySelector(".chat-bubble__status--delivered")?.textContent,
    ).toBe("✓");
    expect(delivered.querySelector(".chat-bubble__substatus")).toBeNull();
  });

  it("never decorates inbound bubbles", () => {
    const handlers = makeHandlers();
    const inbound = renderBubble(
      bubble({ mine: false, status: "sending" }),
      handlers,
    );
    expect(inbound.querySelector(".chat-bubble__substatus")).toBeNull();
  });
});

describe("renderBubble — direction", () => {
  it("uses chat-row--out for my own messages", () => {
    const handlers = makeHandlers();
    const row = renderBubble(bubble({ mine: true }), handlers);
    expect(row.className).toContain("chat-row--out");
  });

  it("uses chat-row--in for incoming messages", () => {
    const handlers = makeHandlers();
    const row = renderBubble(bubble({ mine: false }), handlers);
    expect(row.className).toContain("chat-row--in");
  });
});

describe("bubbleRenderKey — keyed diff for flicker-free re-renders", () => {
  // The conversation pane reuses an existing DOM element whenever a
  // bubble's render key is unchanged across two render passes. That's
  // how the chat-bubble-pop animation is prevented from re-firing
  // every time an unrelated store mutation (presence tick, nearby
  // tick, receipt for another conversation) triggers a sidebar
  // refresh. These tests pin the key shape so any drift surfaces
  // before users see the screen flash again.

  it("renders the key onto the row's data-key attribute", () => {
    const handlers = makeHandlers();
    const row = renderBubble(bubble({ id: "m1", status: "delivered" }), handlers);
    expect(row.dataset.key).toBe(bubbleRenderKey(bubble({ id: "m1", status: "delivered" })));
  });

  it("returns the same key for identical bubbles so the diff reuses the element", () => {
    const a = bubble({ id: "m1", status: "delivered", body: "hi" });
    const b = bubble({ id: "m1", status: "delivered", body: "hi" });
    expect(bubbleRenderKey(a)).toBe(bubbleRenderKey(b));
  });

  it("changes the key when status transitions sending → delivered", () => {
    const sending = bubbleRenderKey(bubble({ id: "m1", status: "sending" }));
    const delivered = bubbleRenderKey(bubble({ id: "m1", status: "delivered" }));
    expect(sending).not.toBe(delivered);
  });

  it("changes the key when failureReason flips", () => {
    const ok = bubbleRenderKey(bubble({ id: "m1", status: "failed" }));
    const annotated = bubbleRenderKey(
      bubble({ id: "m1", status: "failed", failureReason: "timed out" }),
    );
    expect(ok).not.toBe(annotated);
  });

  it("treats two distinct message ids as different keys", () => {
    expect(bubbleRenderKey(bubble({ id: "m1" }))).not.toBe(
      bubbleRenderKey(bubble({ id: "m2" })),
    );
  });
});

describe("renderBubble — reply quote", () => {
  it("renders a quoted-parent block carrying sender and preview", () => {
    const row = renderBubble(
      bubble({
        body: "agreed",
        replyTo: { messageId: "m0", senderName: "Bob", preview: "shall we ship?" },
      }),
      makeHandlers(),
    );
    const quote = row.querySelector(".chat-quote");
    expect(quote).not.toBeNull();
    expect(quote?.textContent).toContain("Bob");
    expect(quote?.textContent).toContain("shall we ship?");
  });

  it("renders no quote block when replyTo is absent", () => {
    const row = renderBubble(bubble({ body: "plain" }), makeHandlers());
    expect(row.querySelector(".chat-quote")).toBeNull();
  });

  it("shows the quote even when the body is an autonomi-only preview", () => {
    const row = renderBubble(
      bubble({
        body: `autonomi://${ADDR}`,
        replyTo: { messageId: "m0", senderName: "Bob", preview: "see this" },
      }),
      makeHandlers(),
    );
    expect(row.querySelector(".chat-quote")).not.toBeNull();
    expect(row.querySelector(".chat-preview")).not.toBeNull();
  });

  it("bubbleRenderKey changes when the quoted parent changes so the diff repaints", () => {
    const none = bubbleRenderKey(bubble({ id: "m1" }));
    const q1 = bubbleRenderKey(
      bubble({ id: "m1", replyTo: { messageId: "p1", senderName: "B", preview: "x" } }),
    );
    const q2 = bubbleRenderKey(
      bubble({ id: "m1", replyTo: { messageId: "p2", senderName: "B", preview: "x" } }),
    );
    expect(q1).not.toBe(none);
    expect(q1).not.toBe(q2);
  });
});

describe("renderBubble — quote-strip click", () => {
  const REPLY = bubble({
    body: "agreed",
    replyTo: { messageId: "p1", senderName: "Bob", preview: "ship it?" },
  });

  it("fires onQuoteClick with the quoted message id", () => {
    const onQuoteClick = vi.fn();
    const row = renderBubble(REPLY, { ...makeHandlers(), onQuoteClick });
    const quote = row.querySelector<HTMLElement>(".chat-quote")!;
    expect(quote.classList.contains("chat-quote--link")).toBe(true);
    quote.click();
    expect(onQuoteClick).toHaveBeenCalledWith("p1");
  });

  it("renders a plain, non-clickable strip without the handler", () => {
    const row = renderBubble(REPLY, makeHandlers());
    const quote = row.querySelector<HTMLElement>(".chat-quote")!;
    expect(quote.classList.contains("chat-quote--link")).toBe(false);
  });
});

describe("renderBubble — reply affordance", () => {
  it("renders the reply button only when an onReply handler is supplied", () => {
    const without = renderBubble(bubble(), makeHandlers());
    expect(without.querySelector(".chat-bubble__reply-btn")).toBeNull();

    const with_ = renderBubble(bubble(), { ...makeHandlers(), onReply: vi.fn() });
    expect(with_.querySelector(".chat-bubble__reply-btn")).not.toBeNull();
  });

  it("clicking the reply button fires onReply with the bubble", () => {
    const onReply = vi.fn();
    const b = bubble({ id: "m7", body: "quote me" });
    const row = renderBubble(b, { ...makeHandlers(), onReply });
    row.querySelector<HTMLButtonElement>(".chat-bubble__reply-btn")!.click();
    expect(onReply).toHaveBeenCalledWith(b);
  });
});

describe("renderBubble — inline image attachment", () => {
  const ATT = { mime: "image/png", width: 8, height: 6, bytes_b64: "iVBORw0KAAA=" };

  it("renders a thumbnail img from the attachment data URL", () => {
    const row = renderBubble(bubble({ body: "", attachment: ATT }), makeHandlers());
    const img = row.querySelector<HTMLImageElement>("img.chat-attachment");
    expect(img).not.toBeNull();
    expect(img!.getAttribute("src")).toBe("data:image/png;base64,iVBORw0KAAA=");
  });

  it("fires onImageOpen with the attachment when the thumbnail is clicked", () => {
    const onImageOpen = vi.fn();
    const row = renderBubble(bubble({ attachment: ATT }), { ...makeHandlers(), onImageOpen });
    row.querySelector<HTMLImageElement>("img.chat-attachment")!.click();
    expect(onImageOpen).toHaveBeenCalledWith(ATT);
  });

  it("renders an image-only bubble (empty body) without suppressing it", () => {
    const row = renderBubble(
      bubble({ mine: false, body: "", attachment: ATT }),
      makeHandlers(),
    );
    expect(row.querySelector("img.chat-attachment")).not.toBeNull();
  });

  it("renders a caption alongside the image", () => {
    const row = renderBubble(bubble({ body: "my cat", attachment: ATT }), makeHandlers());
    expect(row.querySelector("img.chat-attachment")).not.toBeNull();
    expect(row.querySelector(".chat-bubble")?.textContent).toContain("my cat");
  });

  it("bubbleRenderKey changes when an attachment is present", () => {
    expect(bubbleRenderKey(bubble({ attachment: ATT }))).not.toBe(
      bubbleRenderKey(bubble({ attachment: undefined })),
    );
  });
});
