// Render one bridged fediverse public post (M4). The `activity_json` is
// UNTRUSTED ActivityPub content: we extract its text inertly (a detached
// text/html parse, scripts/styles dropped, textContent only, never
// innerHTML, matching the chat markdown posture) and attribute the card
// to the relay-verified actor URL ONLY, never to the body's self-asserted
// actor. Honesty chrome marks it observably public and non-PQ; there is
// no positive "verified" badge on content.

import { extractAutonomiAddresses, mountAutonomiPreview } from "../chat/bubblePreview";

/// A bridged fediverse post handed to the render surface. Mirrors the
/// Rust `PublicPostDelivery` (fetchit-chat client.rs); `activityJson` is
/// the raw `application/activity+json` body, untrusted.
export interface PublicPostDelivery {
  /// Relay-verified actor URL. The SOLE attribution source.
  verifiedActorUrl: string;
  /// Raw ActivityPub JSON-LD text. Untrusted; never rendered as HTML.
  activityJson: string;
}

/// Inertly extract visible text from an untrusted HTML fragment. A
/// detached `text/html` parse executes no scripts and loads no
/// resources; we drop any script/style subtrees and return textContent
/// only, so no markup, attribute, or `javascript:` URL can survive.
function inertText(html: string): string {
  const doc = new DOMParser().parseFromString(html, "text/html");
  doc.querySelectorAll("script, style").forEach((n) => n.remove());
  return (doc.body.textContent ?? "").replace(/\s+/g, " ").trim();
}

/// Pull the Note out of a `Create{Note}` (object nested) or a bare
/// `Note` / `Article` (object at top level). Returns null when the shape
/// is neither, so the caller can degrade gracefully.
function noteOf(activity: unknown): Record<string, unknown> | null {
  if (typeof activity !== "object" || activity === null) return null;
  const a = activity as Record<string, unknown>;
  if (a.type === "Note" || a.type === "Article") return a;
  const obj = a.object;
  if (typeof obj === "object" && obj !== null) {
    return obj as Record<string, unknown>;
  }
  return null;
}

/// Trim the scheme for a compact actor display; the full URL stays in
/// the element title for hover/inspection.
function displayActor(url: string): string {
  return url.replace(/^https?:\/\//, "");
}

/// Render a [`PublicPostDelivery`] into a self-contained card element.
/// Safe against hostile `activity_json`: content is inert text, never
/// HTML, and attribution can only ever read `verifiedActorUrl`.
/// `onReply` (when given) adds the reply-publicly affordance; the
/// callback receives the VERIFIED actor URL, never a body-asserted one,
/// and public reply is the only reply option for fediverse posts.
export function renderFeedPost(
  delivery: PublicPostDelivery,
  onReply?: (verifiedActorUrl: string) => void,
  onAutonomi?: (url: string) => void,
): HTMLElement {
  const root = document.createElement("article");
  root.className = "feed-post";

  // Honesty chrome: observably public, non-PQ. No positive verified badge.
  const badge = document.createElement("div");
  badge.className = "feed-post__badge";
  badge.textContent = "from the fediverse · public, non-PQ";
  root.appendChild(badge);

  // Attribution: the relay-verified actor URL ONLY. The body's
  // self-asserted actor/attributedTo never reaches the DOM.
  const actor = document.createElement("div");
  actor.className = "feed-post__actor";
  actor.textContent = displayActor(delivery.verifiedActorUrl);
  actor.title = delivery.verifiedActorUrl;
  root.appendChild(actor);

  const body = document.createElement("div");
  body.className = "feed-post__body";
  let note: Record<string, unknown> | null = null;
  try {
    note = noteOf(JSON.parse(delivery.activityJson));
  } catch {
    note = null;
  }
  let bodyText = "";
  if (note && typeof note.content === "string") {
    bodyText = inertText(note.content);
    body.textContent = bodyText === "" ? "(empty post)" : bodyText;
  } else {
    body.textContent = "Post content unavailable.";
  }
  root.appendChild(body);

  // Announcement-consumption loop: any autonomi:// address visible in the
  // post text gets a lazy preview that opens in the reader. The body stays
  // inert text; the preview helper (shared with chat bubbles) fetches
  // nothing until the user clicks.
  if (onAutonomi) {
    for (const addr of extractAutonomiAddresses(bodyText)) {
      mountAutonomiPreview(root, addr, { onOpen: onAutonomi });
    }
  }

  // Published timestamp, when present. Rendered verbatim as a machine
  // dateTime; humanizing is a render-time concern for the feed.
  const published =
    note && typeof note.published === "string" ? note.published : "";
  if (published) {
    const time = document.createElement("time");
    time.className = "feed-post__time";
    time.dateTime = published;
    time.textContent = published;
    root.appendChild(time);
  }

  if (onReply) {
    const reply = document.createElement("button");
    reply.type = "button";
    reply.className = "feed-post__reply";
    reply.textContent = "reply publicly";
    reply.addEventListener("click", () => onReply(delivery.verifiedActorUrl));
    root.appendChild(reply);
  }

  return root;
}
