//! Device-side fediverse read feed (M7 P2, pull half).
//!
//! Until the push delivery seam lands, the feed is a client-side pull:
//! for each account the user follows (bridge following list), fetch the
//! newest posts from that actor's public outbox (SSRF-guarded, capped)
//! and merge newest-first. Post HTML is reduced to plain text with
//! [`fetchit_fedi::text::html_to_text`], so no remote markup ever
//! reaches a renderer.

use crate::client::Client;
use crate::error::Result;

/// Accounts pulled per refresh. Follows beyond the cap are skipped this
/// round (newest-recorded first as the bridge returns them).
const FEED_ACCOUNT_CAP: usize = 10;
/// Posts pulled per account.
const FEED_POSTS_PER_ACCOUNT: usize = 10;
/// Posts returned per refresh after the merge.
const FEED_TOTAL_CAP: usize = 50;

/// One feed entry, display-ready (text only).
#[derive(Clone, Debug)]
pub struct FediFeedPost {
    /// Author actor URL.
    pub author_url: String,
    /// Short author label — `user@host` derived from the actor URL.
    pub author_label: String,
    /// Post body as plain text (wire HTML reduced).
    pub text: String,
    /// ISO-8601 publish stamp as served (may be empty). UTC ISO-8601
    /// sorts lexicographically, which is how the merge orders.
    pub published: String,
    /// Link to the post on its home server.
    pub object_url: String,
}

/// `user@host` from an actor URL (`https://host/users/user` and
/// `https://host/actors/user` shapes both reduce; anything else falls
/// back to the host alone). Shared with the FFI so every shell labels
/// accounts identically.
#[must_use]
pub fn author_label(actor_url: &str) -> String {
    let Ok(u) = actor_url.parse::<url::Url>() else {
        return actor_url.to_owned();
    };
    let host = u.host_str().unwrap_or_default().to_owned();
    let name = u
        .path_segments()
        .and_then(|mut s| s.next_back().map(str::to_owned))
        .unwrap_or_default();
    if name.is_empty() {
        host
    } else {
        format!("{name}@{host}")
    }
}

impl Client {
    /// Pull the read feed for our actor `handle`: newest text posts from
    /// followed accounts, merged newest-first. Per-account failures are
    /// skipped, never fatal — a dead server must not break the feed.
    ///
    /// # Errors
    /// [`ChatError::Invalid`](crate::error::ChatError::Invalid) when no
    /// identity is minted or the bridge following list is unreachable
    /// (there is nothing to pull without it).
    pub async fn fetch_fedi_feed(&self, handle: &str, now_ms: u64) -> Result<Vec<FediFeedPost>> {
        let following = self.list_fedi_following(handle, now_ms).await?;
        let mut posts: Vec<FediFeedPost> = Vec::new();
        for entry in following.iter().take(FEED_ACCOUNT_CAP) {
            let Ok(actor_url) = entry.target_actor_url.parse::<url::Url>() else {
                continue;
            };
            let Ok(actor) = fetchit_fedi::lookup::fetch_remote_actor(&actor_url).await else {
                continue;
            };
            // Free ride: the actor doc is already in hand, so record its
            // avatar URL. No image is fetched here — the feed must not
            // slow down for a profile picture.
            self.note_fedi_avatar_source(
                &author_label(&entry.target_actor_url),
                actor.icon_url.as_deref(),
            );
            let Some(outbox) = actor.outbox else {
                continue;
            };
            let Ok(remote) =
                fetchit_fedi::lookup::fetch_outbox_posts(&outbox, FEED_POSTS_PER_ACCOUNT).await
            else {
                continue;
            };
            for p in remote {
                let text = fetchit_fedi::text::html_to_text(&p.content_html);
                if text.is_empty() {
                    continue;
                }
                posts.push(FediFeedPost {
                    author_label: author_label(&p.author_url),
                    author_url: p.author_url,
                    text,
                    published: p.published,
                    object_url: p.object_url,
                });
            }
        }
        // UTC ISO-8601 sorts lexicographically; empty stamps sink last.
        posts.sort_by(|a, b| b.published.cmp(&a.published));
        posts.truncate(FEED_TOTAL_CAP);
        Ok(posts)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn author_label_reduces_mastodon_and_fetchit_shapes() {
        assert_eq!(
            author_label("https://fosstodon.org/users/happyborg"),
            "happyborg@fosstodon.org"
        );
        assert_eq!(
            author_label("https://etchit.io/actors/josh"),
            "josh@etchit.io"
        );
        assert_eq!(author_label("not a url"), "not a url");
    }

    #[test]
    fn iso8601_desc_sort_is_newest_first() {
        let mut v = vec![
            "2026-07-12T10:00:00Z".to_owned(),
            "2026-07-13T06:00:00Z".to_owned(),
            String::new(),
            "2026-07-13T05:59:59Z".to_owned(),
        ];
        v.sort_by(|a, b| b.cmp(a));
        assert_eq!(
            v,
            vec![
                "2026-07-13T06:00:00Z".to_owned(),
                "2026-07-13T05:59:59Z".to_owned(),
                "2026-07-12T10:00:00Z".to_owned(),
                String::new(),
            ]
        );
    }
}
