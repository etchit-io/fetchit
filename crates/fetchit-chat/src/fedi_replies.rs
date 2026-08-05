//! Device-side fediverse thread pull (M7 P5).
//!
//! The read feed shows posts but not the conversation under them,
//! because a reply lives in the REPLIER's outbox on THEIR server —
//! walking the accounts we follow can never reach it. An `ActivityPub`
//! Note carries a `replies` Collection instead, so a thread is pulled on
//! demand exactly the way [`crate::fedi_feed`] pulls the feed:
//! device-side, SSRF-guarded, capped, and stored nowhere. No relay and
//! no bridge learns that a thread was opened, and neither stores a byte
//! of it.
//!
//! Reply bodies are reduced to plain text with
//! [`fetchit_fedi::text::html_to_text`] before they leave this module,
//! and every reply author runs the same denylist gate the feed runs — a
//! blocked account must not reach the reader through a thread it was
//! filtered out of the feed for.

use crate::client::Client;
use crate::error::{ChatError, Result};
use crate::fedi_feed::{author_label, FediFeedPost, FediPostMention};

/// One post's replies, plus what the origin server actually told us.
#[derive(Clone, Debug, Default)]
pub struct FediThread {
    /// Replies oldest-first — a conversation reads down the page.
    /// Display-ready (text only), denylist-filtered.
    pub replies: Vec<FediFeedPost>,
    /// The post's home server published a `replies` collection we could
    /// read.
    ///
    /// `false` with an empty [`Self::replies`] means "this server does
    /// not tell us about replies"; `true` with an empty list means
    /// "nobody has replied yet". Those are different facts, and a reader
    /// that renders them with the same sentence is lying about one.
    pub replies_served: bool,
}

impl Client {
    /// Pull the thread under the post at `object_url`.
    ///
    /// Engine caps apply (at most two collection pages, twenty
    /// dereferenced replies, fifty replies kept, one wall-clock budget
    /// across the lot — see
    /// [`fetchit_fedi::lookup::fetch_thread_replies`]). A reply whose
    /// author is denylisted is dropped, and one whose body reduces to
    /// nothing is skipped; neither is an error.
    ///
    /// No display name rides on a reply. A Note carries only
    /// `attributedTo`, and the name lives in the author's actor
    /// document — one extra fetch per distinct replier, on a screen that
    /// already spends up to twenty. The `user@host` label stands
    /// instead, which is the identity that matters anyway.
    ///
    /// # Errors
    /// [`ChatError::Invalid`] when `object_url` is not a URL, or when
    /// the POST ITSELF could not be fetched. Everything after that
    /// degrades to fewer replies rather than an error — a half-read
    /// thread is still a thread.
    pub async fn fetch_fedi_thread(&self, object_url: &str) -> Result<FediThread> {
        let url: url::Url = object_url
            .trim()
            .parse()
            .map_err(|e| ChatError::Invalid(format!("post url: {e}")))?;
        let thread = fetchit_fedi::lookup::fetch_thread_replies(&url)
            .await
            .map_err(|e| ChatError::Invalid(format!("couldn't load the replies: {e}")))?;

        // One local read for the whole thread, joined per reply below. A
        // load failure costs hearts, never the conversation. A device
        // with no minted handle reads threads all the same — it simply
        // has no likes of its own to join.
        let liked: std::collections::HashSet<String> = self
            .layout()
            .and_then(crate::fedi_mint_state::active_handle)
            .and_then(|h| self.fedi_liked_posts(&h).ok())
            .unwrap_or_default()
            .into_iter()
            .collect();

        let mut replies = Vec::with_capacity(thread.replies.len());
        for p in thread.replies {
            if self.gate_actor_url(&p.author_url).await.is_err() {
                log::info!(
                    "[fedi] thread: dropping reply from denylisted {}",
                    p.author_url
                );
                continue;
            }
            let text = fetchit_fedi::text::html_to_text(&p.content_html);
            if text.is_empty() {
                continue;
            }
            replies.push(FediFeedPost {
                author_label: author_label(&p.author_url),
                author_url: p.author_url,
                author_name: None,
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
        Ok(FediThread {
            replies,
            replies_served: thread.collection_served,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The exact per-reply predicate `fetch_fedi_thread` runs: a blocked
    /// author is dropped from the conversation, everyone else stays, and
    /// the trailing-slash variant cannot slip past.
    #[tokio::test]
    async fn denylisted_reply_authors_are_dropped() {
        use crate::public::{check_optional_actor_url_denylist, tests::StubDenylist};

        let d = StubDenylist::new(["https://attacker.example/users/eve"]);
        let authors = [
            "https://mastodon.example/users/alice",
            "https://attacker.example/users/eve",
            "https://attacker.example/users/eve/",
            "https://fosstodon.org/users/happyborg",
        ];
        let mut kept = Vec::new();
        for a in authors {
            if check_optional_actor_url_denylist(Some(&d), a).await.is_ok() {
                kept.push(a);
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

    /// Fail-open matches the feed: a device that never installed a
    /// denylist consumer must still see the whole conversation.
    #[tokio::test]
    async fn no_denylist_installed_keeps_every_reply() {
        use crate::public::check_optional_actor_url_denylist;

        check_optional_actor_url_denylist(None, "https://attacker.example/users/eve")
            .await
            .unwrap();
    }

    #[test]
    fn a_reply_whose_body_reduces_to_nothing_is_skipped() {
        // The projection contract: wire HTML is reduced before the row
        // exists, and a Note that was pure markup leaves no text to draw.
        assert!(fetchit_fedi::text::html_to_text("<p></p>").is_empty());
        assert_eq!(
            fetchit_fedi::text::html_to_text("<p>Right <b>here</b>.</p>"),
            "Right here.",
        );
    }

    #[test]
    fn an_empty_thread_and_a_silent_server_are_different_values() {
        // The one distinction the whole empty state rests on.
        let nobody_replied = FediThread {
            replies: Vec::new(),
            replies_served: true,
        };
        let server_said_nothing = FediThread::default();
        assert!(nobody_replied.replies.is_empty());
        assert!(nobody_replied.replies_served);
        assert!(server_said_nothing.replies.is_empty());
        assert!(!server_said_nothing.replies_served);
    }
}
