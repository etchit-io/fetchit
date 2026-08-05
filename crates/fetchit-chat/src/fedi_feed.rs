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

/// One mention on a feed post: the visible `@user@host` text and the
/// actor URL behind it. A shell spans the text and opens the profile
/// for the URL; both are remote-authored, so acting on either re-enters
/// the gated resolve path ([`crate::fedi_profile`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FediPostMention {
    /// Mention text as written in the body, e.g. `@alice@mastodon.example`.
    pub name: String,
    /// Actor URL the authoring server resolved the mention to.
    pub href: String,
}

/// One feed entry, display-ready (text only).
#[derive(Clone, Debug)]
pub struct FediFeedPost {
    /// Author actor URL.
    pub author_url: String,
    /// Short author label — `user@host` derived from the actor URL.
    pub author_label: String,
    /// The author's chosen display name, when their actor document
    /// publishes one. A row shows this ahead of [`Self::author_label`];
    /// `None` means fall back to the label.
    pub author_name: Option<String>,
    /// Post body as plain text (wire HTML reduced).
    pub text: String,
    /// ISO-8601 publish stamp as served (may be empty). UTC ISO-8601
    /// sorts lexicographically, which is how the merge orders.
    pub published: String,
    /// Link to the post on its home server.
    pub object_url: String,
    /// `Mention` tags on the post, capped engine-side.
    pub mentions: Vec<FediPostMention>,
    /// This device has liked the post
    /// ([`crate::fedi_like`]). Device state, not a remote count —
    /// there is no cheap `ActivityPub` source for a like total, so v1
    /// renders the toggle and no number.
    pub liked: bool,
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

/// The display name to stamp on a post, given the FOLLOWED account's
/// actor id + name. An outbox can carry a Note attributed to somebody
/// else; stamping this account's name onto it would misattribute the
/// post, so the name rides only on an exact author-id match.
fn name_for_author(
    post_author_url: &str,
    actor_id: &str,
    actor_name: Option<&str>,
) -> Option<String> {
    if post_author_url == actor_id {
        actor_name.map(str::to_owned)
    } else {
        None
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
        // The liked-set is one local read for the whole refresh, joined
        // per post below. A load failure costs hearts, never the feed.
        let liked: std::collections::HashSet<String> = self
            .fedi_liked_posts(handle)
            .unwrap_or_default()
            .into_iter()
            .collect();
        let mut posts: Vec<FediFeedPost> = Vec::new();
        for entry in following.iter().take(FEED_ACCOUNT_CAP) {
            // A denylisted account is skipped WHOLE — before the actor
            // fetch, so its server never sees a request from this
            // device, and therefore before the outbox fetch that would
            // pull its posts into the feed. A follow row can outlive the
            // block (the row lives at the bridge, the list at the trust
            // service), so the gate has to run per refresh rather than
            // only at follow time. Fail-open with no denylist installed.
            if self.gate_actor_url(&entry.target_actor_url).await.is_err() {
                log::info!(
                    "[fedi] feed: skipping denylisted account {}",
                    entry.target_actor_url
                );
                continue;
            }
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
            // Same free ride for the display name. A Note carries only
            // `attributedTo` (a URL), so the actor document is the only
            // place a name is available without a second request — and
            // it is only this account's name, so it is applied to posts
            // this account actually authored.
            let actor_id = actor.id.to_string();
            let actor_name = actor.name.clone();
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
                let author_name = name_for_author(&p.author_url, &actor_id, actor_name.as_deref());
                posts.push(FediFeedPost {
                    author_label: author_label(&p.author_url),
                    author_url: p.author_url,
                    author_name,
                    liked: liked.contains(&p.object_url),
                    text,
                    published: p.published,
                    object_url: p.object_url,
                    mentions: p
                        .mentions
                        .into_iter()
                        .map(|m| FediPostMention {
                            name: m.name,
                            href: m.href,
                        })
                        .collect(),
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
    fn a_display_name_is_only_applied_to_that_actors_own_posts() {
        let actor_id = "https://m.example/users/g";
        assert_eq!(
            name_for_author(actor_id, actor_id, Some("Gargron")),
            Some("Gargron".to_owned()),
        );
        // A boosted / relayed Note attributed elsewhere must NOT wear
        // the followed account's name.
        assert_eq!(
            name_for_author(
                "https://elsewhere.example/users/x",
                actor_id,
                Some("Gargron")
            ),
            None,
        );
        // An account that publishes no name leaves the label to stand.
        assert_eq!(name_for_author(actor_id, actor_id, None), None);
    }

    #[test]
    fn mentions_project_one_for_one_from_the_lookup_shape() {
        let remote = vec![
            fetchit_fedi::lookup::MentionRef {
                name: "@alice@mastodon.example".to_owned(),
                href: "https://mastodon.example/users/alice".to_owned(),
            },
            fetchit_fedi::lookup::MentionRef {
                name: "@bob@fosstodon.org".to_owned(),
                href: "https://fosstodon.org/users/bob".to_owned(),
            },
        ];
        let projected: Vec<FediPostMention> = remote
            .into_iter()
            .map(|m| FediPostMention {
                name: m.name,
                href: m.href,
            })
            .collect();
        assert_eq!(
            projected,
            vec![
                FediPostMention {
                    name: "@alice@mastodon.example".to_owned(),
                    href: "https://mastodon.example/users/alice".to_owned(),
                },
                FediPostMention {
                    name: "@bob@fosstodon.org".to_owned(),
                    href: "https://fosstodon.org/users/bob".to_owned(),
                },
            ],
        );
    }

    #[test]
    fn liked_state_joins_on_the_object_url() {
        // The join key is the post URL, which is what the like driver
        // records — a mismatch here would render every heart empty.
        let liked: std::collections::HashSet<String> =
            ["https://m.example/@g/1".to_owned()].into_iter().collect();
        assert!(liked.contains("https://m.example/@g/1"));
        assert!(!liked.contains("https://m.example/@g/2"));
    }

    /// The exact per-account predicate `fetch_fedi_feed` runs before it
    /// touches a followed account's server: a blocked actor is dropped
    /// from the round, everyone else is pulled.
    #[tokio::test]
    async fn denylisted_accounts_are_dropped_before_any_fetch() {
        use crate::public::{check_optional_actor_url_denylist, tests::StubDenylist};

        let d = StubDenylist::new(["https://attacker.example/users/eve"]);
        let following = [
            "https://mastodon.example/users/alice",
            "https://attacker.example/users/eve",
            // Trailing-slash variant of the blocked actor: the gate
            // canonicalizes, so it must not slip through as a second
            // fetchable account.
            "https://attacker.example/users/eve/",
            "https://fosstodon.org/users/happyborg",
        ];
        let mut kept = Vec::new();
        for url in following {
            if check_optional_actor_url_denylist(Some(&d), url)
                .await
                .is_ok()
            {
                kept.push(url);
            }
        }
        assert_eq!(
            kept,
            vec![
                "https://mastodon.example/users/alice",
                "https://fosstodon.org/users/happyborg",
            ],
        );
    }

    /// No denylist installed means no account is skipped — the feed must
    /// not silently empty itself on a client that never installed a
    /// consumer.
    #[tokio::test]
    async fn no_denylist_installed_keeps_every_account() {
        use crate::public::check_optional_actor_url_denylist;

        for url in [
            "https://mastodon.example/users/alice",
            "https://attacker.example/users/eve",
        ] {
            check_optional_actor_url_denylist(None, url).await.unwrap();
        }
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
