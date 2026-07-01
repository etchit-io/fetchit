import { describe, expect, it, vi } from "vitest";
import { renderFeedPost, type PublicPostDelivery } from "./feedPost";

// A relay-verified actor URL. Attribution must come from this field only,
// never from anything inside the (untrusted) activity body.
const VERIFIED = "https://mastodon.example/users/real";

function create(content: string, extra: Record<string, unknown> = {}): PublicPostDelivery {
  return {
    verifiedActorUrl: VERIFIED,
    activityJson: JSON.stringify({
      type: "Create",
      actor: "https://body-claims.example/users/whoever",
      object: {
        type: "Note",
        content,
        published: "2026-06-09T12:00:00Z",
        attributedTo: "https://body-claims.example/users/whoever",
        ...extra,
      },
    }),
  };
}

describe("renderFeedPost", () => {
  it("renders the note content as text and attributes to the verified actor", () => {
    const el = renderFeedPost(create("<p>Hello <strong>fediverse</strong></p>"));
    expect(el.classList.contains("feed-post")).toBe(true);
    const body = el.querySelector(".feed-post__body");
    expect(body?.textContent).toContain("Hello fediverse");
    const actor = el.querySelector(".feed-post__actor");
    expect(actor?.textContent).toContain("mastodon.example");
  });

  it("attributes to verified_actor_url ONLY, ignoring the body's self-asserted actor", () => {
    const el = renderFeedPost(create("hi"));
    // the spoofed actor/attributedTo from the body must never surface
    expect(el.outerHTML).not.toContain("body-claims.example");
    expect(el.querySelector(".feed-post__actor")?.textContent).toContain(VERIFIED.replace("https://", ""));
  });

  it("neutralizes hostile content: no script/img nodes, nothing executable", () => {
    const el = renderFeedPost(
      create('<script>alert(1)</script><img src=x onerror="alert(2)"><a href="javascript:alert(3)">tap</a>safe-text'),
    );
    // No live script or img element ever materializes in the DOM
    expect(el.querySelector("script")).toBeNull();
    expect(el.querySelector("img")).toBeNull();
    // No event handler or javascript: scheme survives into the markup
    const html = el.outerHTML.toLowerCase();
    expect(html).not.toContain("onerror");
    expect(html).not.toContain("javascript:");
    expect(html).not.toContain("<script");
    // The benign text still shows through
    expect(el.querySelector(".feed-post__body")?.textContent).toContain("safe-text");
  });

  it("carries honesty chrome: a fediverse/public label, no positive verified badge", () => {
    const el = renderFeedPost(create("hi"));
    const label = el.textContent?.toLowerCase() ?? "";
    expect(label).toContain("fediverse");
    expect(label).toContain("public");
    // The honesty floor: never a positive "verified" claim on content.
    expect(label).not.toContain("verified");
  });

  it("degrades gracefully on malformed activity JSON without throwing", () => {
    const el = renderFeedPost({ verifiedActorUrl: VERIFIED, activityJson: "{not json" });
    expect(el.classList.contains("feed-post")).toBe(true);
    // still attributes to the verified actor and says the body is unavailable
    expect(el.querySelector(".feed-post__actor")?.textContent).toContain("mastodon.example");
    expect(el.querySelector(".feed-post__body")?.textContent?.toLowerCase()).toContain("unavailable");
  });

  it("handles a bare Note (object at top level) as well as Create{Note}", () => {
    const delivery: PublicPostDelivery = {
      verifiedActorUrl: VERIFIED,
      activityJson: JSON.stringify({
        type: "Note",
        content: "<p>bare note</p>",
        published: "2026-06-09T12:00:00Z",
      }),
    };
    const el = renderFeedPost(delivery);
    expect(el.querySelector(".feed-post__body")?.textContent).toContain("bare note");
  });

  it("reply affordance fires with the VERIFIED actor, never the body actor", () => {
    const onReply = vi.fn();
    const el = renderFeedPost(create("x"), onReply);
    el.querySelector<HTMLButtonElement>(".feed-post__reply")!.click();
    expect(onReply).toHaveBeenCalledTimes(1);
    expect(onReply).toHaveBeenCalledWith(VERIFIED);
  });

  it("renders no reply affordance without a callback", () => {
    const el = renderFeedPost(create("x"));
    expect(el.querySelector(".feed-post__reply")).toBeNull();
  });

  it("surfaces an autonomi:// address in the post text as a preview that opens in the reader", () => {
    const onAutonomi = vi.fn();
    const addr = "a".repeat(64);
    const el = renderFeedPost(create(`look at this autonomi://${addr} neat`), undefined, onAutonomi);
    const card = el.querySelector(".chat-preview");
    expect(card).not.toBeNull();
    expect(card?.querySelector(".chat-preview__addr")?.getAttribute("title")).toBe(`autonomi://${addr}`);
    // "Open" hands the full url to the reader-open callback.
    el.querySelector<HTMLButtonElement>(".chat-preview__btn--ghost")!.click();
    expect(onAutonomi).toHaveBeenCalledWith(`autonomi://${addr}`);
    // The body itself stays inert text, never a live anchor.
    expect(el.querySelector(".feed-post__body")?.textContent).toContain(`autonomi://${addr}`);
    expect(el.querySelector(".feed-post__body a")).toBeNull();
  });

  it("dedupes repeated addresses into a single preview card", () => {
    const addr = "c".repeat(64);
    const el = renderFeedPost(
      create(`autonomi://${addr} and again autonomi://${addr}`),
      undefined,
      vi.fn(),
    );
    expect(el.querySelectorAll(".chat-preview")).toHaveLength(1);
  });

  it("renders no preview card when the body has no autonomi address", () => {
    const el = renderFeedPost(create("just text, no links here"), undefined, vi.fn());
    expect(el.querySelector(".chat-preview")).toBeNull();
  });

  it("renders no preview card without an onAutonomi callback even if an address is present", () => {
    const addr = "b".repeat(64);
    const el = renderFeedPost(create(`autonomi://${addr}`));
    expect(el.querySelector(".chat-preview")).toBeNull();
  });
});
