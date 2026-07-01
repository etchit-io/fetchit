// The fediverse public-post feed: a live, newest-first list of M4
// bridged posts, each rendered as an inert card by `renderFeedPost`.
// Append-only and deduped by activity id (the feed is live-only;
// history backfill is a post-launch concern), with a DOM cap so a long
// session cannot grow the list without bound.

import { renderFeedPost, type PublicPostDelivery } from "./feedPost";

/// Max cards kept in the DOM. Matches the Rust broadcast channel cap
/// (`PUBLIC_POST_CHANNEL_CAP`); older cards drop off the bottom.
const FEED_CAP = 256;

/// Imperative handle over a mounted feed.
export interface FeedHandle {
  /// Add one post (newest-first). A duplicate (same activity id) is a
  /// no-op, so a reconnect replay cannot double-render.
  add(delivery: PublicPostDelivery): void;
  /// Drop every post and restore the empty state.
  clear(): void;
  /// Number of distinct posts currently shown.
  count(): number;
}

/// Stable per-post key: the ActivityPub `id` (or nested object id) when
/// present, else the actor plus raw body. Used for dedupe only.
function feedKey(d: PublicPostDelivery): string {
  try {
    const a = JSON.parse(d.activityJson) as Record<string, unknown>;
    const nested = a.object as Record<string, unknown> | undefined;
    const id = a.id ?? nested?.id;
    if (typeof id === "string" && id !== "") return id;
  } catch {
    // fall through to the body-derived key
  }
  return `${d.verifiedActorUrl} ${d.activityJson}`;
}

/// Mount a feed into `host` and return a handle to push posts onto it.
/// `onReply` threads the per-card reply-publicly affordance through to
/// the pane (which targets the compose surface at the verified actor).
export function mountFeed(
  host: HTMLElement,
  onReply?: (verifiedActorUrl: string) => void,
  onAutonomi?: (url: string) => void,
): FeedHandle {
  host.replaceChildren();
  host.className = "feed";

  const empty = document.createElement("div");
  empty.className = "feed__empty";
  empty.textContent = "No public posts yet.";

  const list = document.createElement("div");
  list.className = "feed__list";

  host.append(empty, list);

  const seen = new Set<string>();

  const add = (delivery: PublicPostDelivery): void => {
    const key = feedKey(delivery);
    if (seen.has(key)) return;
    seen.add(key);
    const card = renderFeedPost(delivery, onReply, onAutonomi);
    card.dataset.key = key;
    list.prepend(card);
    empty.hidden = true;
    while (list.childElementCount > FEED_CAP) {
      const oldest = list.lastElementChild as HTMLElement | null;
      if (!oldest) break;
      if (oldest.dataset.key) seen.delete(oldest.dataset.key);
      oldest.remove();
    }
  };

  const clear = (): void => {
    list.replaceChildren();
    seen.clear();
    empty.hidden = false;
  };

  return { add, clear, count: () => seen.size };
}
