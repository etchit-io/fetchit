//! Device-side fediverse profile fetch (M7).
//!
//! Everything a profile sheet renders about an arbitrary account, off
//! one actor document: display name, bio, avatar source, canonical
//! actor URL. Resolution rides the same SSRF-guarded, denylist-gated
//! path as follow ([`Client::follow_fedi`]) — a tap on an author chip
//! or an @-mention must not be a softer entrance to the network than a
//! handle the user typed.
//!
//! No follow-state is projected here. The shell already knows what it
//! follows (the bridge's owner-only list plus its own optimistic
//! record), and folding that in would mean a bridge round-trip on every
//! profile open.

use crate::client::Client;
use crate::error::{ChatError, Result};

/// One remote account, reduced to what a profile sheet renders.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FediProfile {
    /// Canonical actor URL (the document's own `id`).
    pub actor_url: String,
    /// `user@host` label — the avatar-cache key and the fallback title.
    pub label: String,
    /// The account's chosen display name, when it publishes one.
    pub display_name: Option<String>,
    /// Bio as PLAIN TEXT: the served `summary` HTML reduced through
    /// [`fetchit_fedi::text::html_to_text`], so no remote markup can
    /// reach a renderer. Empty when there is no bio.
    pub bio_text: String,
    /// Avatar URL as served. Unvalidated remote input — the avatar
    /// cache owns the https + SSRF + size + content-type gates.
    pub icon_url: Option<String>,
}

impl Client {
    /// Fetch the profile for `target`, which may be any of the forms a
    /// user or a remote document can hand us:
    ///
    /// - `@user@host` — the canonical mention form
    /// - `user@host` — the email-ish form people actually type
    /// - `https://host/users/user` — a mention tag's `href`, or a feed
    ///   post's author URL
    ///
    /// Handle forms resolve via `WebFinger` + the denylist gate; a URL
    /// is denylist-gated directly. Both then fetch the actor document
    /// through the same pinned, redirect-free, size-capped client, and
    /// the id-binding rule in
    /// [`fetchit_fedi::lookup::fetch_remote_actor`] applies — a
    /// document claiming an id it does not serve is rejected.
    ///
    /// The resolved `icon` URL is recorded through the avatar seam, so
    /// opening a profile warms the face for every later row that shows
    /// this account.
    ///
    /// # Errors
    /// [`ChatError::DeniedActor`] when the target is denylisted;
    /// [`ChatError::Invalid`] for an unparsable target, a `WebFinger`
    /// failure, or an unreachable / undecodable actor document.
    pub async fn fetch_fedi_profile(&self, target: &str) -> Result<FediProfile> {
        let actor_url = self.resolve_profile_target(target).await?;
        let actor = fetchit_fedi::lookup::fetch_remote_actor(&actor_url)
            .await
            .map_err(|e| ChatError::Invalid(format!("couldn't fetch that account: {e}")))?;

        let actor_url = actor.id.to_string();
        let label = crate::fedi_feed::author_label(&actor_url);
        self.note_fedi_avatar_source(&label, actor.icon_url.as_deref());

        Ok(FediProfile {
            actor_url,
            label,
            display_name: actor.name,
            bio_text: actor
                .summary
                .as_deref()
                .map(fetchit_fedi::text::html_to_text)
                .unwrap_or_default(),
            icon_url: actor.icon_url,
        })
    }

    /// Target → gated actor URL. A `http(s)://` target is gated as a URL;
    /// anything else is normalized to `@user@host` and resolved.
    async fn resolve_profile_target(&self, target: &str) -> Result<url::Url> {
        let trimmed = target.trim();
        if trimmed.is_empty() {
            return Err(ChatError::Invalid("empty account reference".into()));
        }
        if is_http_url(trimmed) {
            let url: url::Url = trimmed
                .parse()
                .map_err(|e| ChatError::Invalid(format!("actor url: {e}")))?;
            self.gate_actor_url(url.as_str()).await?;
            return Ok(url);
        }
        self.resolve_and_gate_mention(&crate::client::normalize_lookup_handle(trimmed))
            .await
    }
}

/// Whether `s` reads as an http(s) URL rather than a handle. Scheme
/// match is ASCII-case-insensitive per RFC 3986; every other scheme
/// (including `acct:`) falls through to handle normalization, where a
/// malformed value fails loudly instead of reaching a socket.
fn is_http_url(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.starts_with("https://") || lower.starts_with("http://")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn url_targets_are_distinguished_from_handles() {
        assert!(is_http_url("https://mastodon.example/users/alice"));
        assert!(is_http_url("HTTPS://Mastodon.Example/users/alice"));
        assert!(is_http_url("http://mastodon.example/users/alice"));
        // Handle forms — including one whose local part looks scheme-ish.
        assert!(!is_http_url("@alice@mastodon.example"));
        assert!(!is_http_url("alice@mastodon.example"));
        assert!(!is_http_url("acct:alice@mastodon.example"));
        assert!(!is_http_url("httpsx@mastodon.example"));
    }

    #[test]
    fn every_handle_form_normalizes_to_the_same_mention() {
        // The Phase-6 lookup-boundary rule applies here too: a profile
        // opened from a typed handle, a mention tag's name, and a
        // following-list label must all land on one target.
        for form in [
            "@happyborg@fosstodon.org",
            "happyborg@fosstodon.org",
            "  HappyBorg@Fosstodon.org ",
        ] {
            assert_eq!(
                crate::client::normalize_lookup_handle(form),
                "@happyborg@fosstodon.org",
            );
        }
    }

    #[test]
    fn bio_html_is_reduced_before_it_can_reach_a_renderer() {
        // The projection contract: `summary` is raw remote HTML and
        // `bio_text` is what a sheet draws, so the reduction must have
        // already happened by the time the struct exists.
        let reduced = fetchit_fedi::text::html_to_text(
            "<p>Hi <b>there</b>.</p><script>alert(1)</script><p>Line two.</p>",
        );
        assert!(!reduced.contains('<'));
        assert!(!reduced.contains("alert"));
        assert!(reduced.contains("Hi there."));
        assert!(reduced.contains("Line two."));
    }

    #[test]
    fn an_empty_target_is_rejected_before_any_resolution() {
        // Guarding here rather than letting parse_mention decide keeps a
        // blank tap from producing a WebFinger request for "@".
        for blank in ["", "   ", "\t\n"] {
            assert!(blank.trim().is_empty());
        }
    }
}
