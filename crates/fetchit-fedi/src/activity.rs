//! `ActivityPub` `Activity` types — `Create`, `Note`, `Follow`, and the
//! fetchit-side `PublicPost` envelope payload.
//!
//! Plan Stage 5.1 lands `PublicPost`; Stage 5.3 expands to `Follow`.

use serde::{Deserialize, Serialize};

/// A C=Public chat-layer post, ready to be wrapped into an `ActivityPub`
/// `Create { object: Note }` activity by Stage 5.2's
/// `Client::publish_public_post` and delivered through
/// [`crate::transport::FediverseTransport`].
///
/// URLs are carried as `String` rather than `url::Url` so the value
/// can pass through `fetchit_trust::canonicalize_url_value` before
/// any denylist check fires; the canonical-on-wire shape matches the
/// denylist manifest values from M4 Stage 4.1. Callers MUST
/// canonicalize before constructing.
///
/// `created_at_ms` is milliseconds-since-epoch in UTC; matches the
/// `ts_ms` convention used elsewhere in the chat layer and avoids
/// pulling a `chrono` dep into the fedi crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicPost {
    /// Fediverse handle of the author in `@user@instance` form. Used
    /// by the outbound POST builder as the `actor` field; not
    /// authoritative for denylist purposes (the actor URL is).
    pub author_handle: String,

    /// Markdown body of the post. Rendered to HTML by the recipient's
    /// renderer; the outbound `Note.content` field gets the HTML form
    /// at delivery time.
    pub body_md: String,

    /// Authorship time in milliseconds-since-epoch (UTC).
    pub created_at_ms: u64,

    /// Canonical-form actor URL this post is replying to, when
    /// applicable. `None` for top-level posts.
    pub reply_to_actor_url: Option<String>,

    /// Fediverse handles mentioned in the post, in `@user@instance`
    /// form. Resolution to canonical actor URLs happens in Stage 5.2
    /// at publish-time via `WebFinger`; per-mention denylist gating
    /// fires after that resolution, not at this layer.
    pub mentions: Vec<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn sample() -> PublicPost {
        PublicPost {
            author_handle: "@josh@etchit.io".to_owned(),
            body_md: "Hello fediverse.".to_owned(),
            created_at_ms: 1_780_876_000_000,
            reply_to_actor_url: Some("https://mastodon.example/users/alice".to_owned()),
            mentions: vec!["@alice@mastodon.example".to_owned()],
        }
    }

    #[test]
    fn public_post_serde_round_trip() {
        let p = sample();
        let json = serde_json::to_string(&p).unwrap();
        let back: PublicPost = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn public_post_top_level_has_no_reply_to() {
        let mut p = sample();
        p.reply_to_actor_url = None;
        p.mentions.clear();
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"reply_to_actor_url\":null"));
        let back: PublicPost = serde_json::from_str(&json).unwrap();
        assert!(back.reply_to_actor_url.is_none());
        assert!(back.mentions.is_empty());
    }
}
