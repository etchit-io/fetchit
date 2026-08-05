//! C=Public chat-layer surface — denylist gating helpers for the
//! Stage 5 fediverse publish path.
//!
//! This module owns the denylist gating primitives;
//! `Client::publish_public_post` consumes them. Splitting the gate
//! from the publish-driver keeps the
//! check synchronously testable against a stub
//! [`DenylistCheck`] without standing up the full HTTPS-POST
//! stack and lets the desktop UI confirmation modal
//! pre-flight the same gate before the user commits.
//!
//! Per [`crate::error::ChatError::DeniedActor`] doc, the actor
//! URLs passed in MUST already be canonical-form. Mention handles
//! (`@user@instance`) are NOT gated here because their canonical
//! actor URL is only known after the Stage 5.2 `WebFinger`
//! resolution; per-mention gating fires there.

use crate::denylist::DenylistCheck;
use crate::error::ChatError;
use fetchit_fedi::{parse_mention, resolve_handle, PublicPost};
use url::Url;

/// Single-shot denylist check against one actor URL.
///
/// The URL is CANONICALIZED here (same rules the denylist publish side
/// enforces — one trailing slash stripped, no query/fragment/userinfo)
/// before the lookup, because the consumer index matches exact
/// canonical form: without this, a denylisted actor evades the gate by
/// self-serving its `id` with a trailing slash or a stray `?x`
/// (cross-review 2026-08-03 round 2). A URL that fails
/// canonicalization is DENIED outright: no legitimate `ActivityPub`
/// actor id carries those shapes, and a gate against hostile actors
/// must fail closed on degenerate input.
///
/// Returns [`ChatError::DeniedActor`] when the URL is blocked (or
/// degenerate), `Ok(())` when not. Intended for per-mention gating
/// after `WebFinger` resolution and for the inbound follow-accept gate.
///
/// # Errors
/// Surfaces [`ChatError::DeniedActor`] when `actor_url` is on the
/// community denylist or cannot be canonicalized.
pub async fn check_actor_url_denylist(
    denylist: &dyn DenylistCheck,
    actor_url: &str,
) -> Result<(), ChatError> {
    let Ok(canonical) = fetchit_trust_types::canonicalize_url_value(actor_url) else {
        return Err(ChatError::DeniedActor {
            actor_url: actor_url.to_owned(),
        });
    };
    if denylist.is_blocked_actor(&canonical).await {
        return Err(ChatError::DeniedActor {
            actor_url: actor_url.to_owned(),
        });
    }
    Ok(())
}

/// [`check_actor_url_denylist`] for callers that may not have a
/// denylist wired at all.
///
/// `None` is the not-installed case (a client built before
/// `install_m3_denylist`, or a shell that never installs one) and passes
/// — fail-open, matching the "empty cache returns `false`" semantics the
/// published manifest is the source of truth for. A wired denylist gates
/// exactly as [`check_actor_url_denylist`] does, degenerate-input
/// fail-closed included.
///
/// This is the whole body of `Client::gate_actor_url`; it lives here as
/// a free function so every gated surface (the fediverse read feed, the
/// profile/lookup path, the inbound follow-accept loop) shares one
/// implementation that is testable against a stub without standing up a
/// `Client`.
///
/// # Errors
/// Surfaces [`ChatError::DeniedActor`] when a wired denylist blocks
/// `actor_url` or the URL cannot be canonicalized.
pub async fn check_optional_actor_url_denylist(
    denylist: Option<&dyn DenylistCheck>,
    actor_url: &str,
) -> Result<(), ChatError> {
    match denylist {
        Some(dl) => check_actor_url_denylist(dl, actor_url).await,
        None => Ok(()),
    }
}

/// Pre-flight gate for a full [`PublicPost`] — checks every
/// fediverse-side actor URL the post carries at the chat layer.
///
/// At Stage 5.1-chat scope, "carries at the chat layer" means
/// `reply_to_actor_url` only. Mentions are `@user@instance`
/// handles and aren't yet URLs; Stage 5.2's
/// `Client::publish_public_post` runs `WebFinger` resolution on
/// each mention and then calls [`check_actor_url_denylist`] per
/// resolved URL before delivering to that instance.
///
/// # Errors
/// Surfaces [`ChatError::DeniedActor`] with the first blocked
/// `reply_to_actor_url` found.
pub async fn check_publish_denylist(
    denylist: &dyn DenylistCheck,
    post: &PublicPost,
) -> Result<(), ChatError> {
    if let Some(ref reply_to) = post.reply_to_actor_url {
        check_actor_url_denylist(denylist, reply_to).await?;
    }
    Ok(())
}

/// Resolve a `@user@instance` mention to its canonical actor URL via
/// `WebFinger`, then gate that URL through `denylist.is_blocked_actor`.
///
/// The composed-helper for Stage 5.2's per-mention publish loop: each
/// mention on a `PublicPost` goes through here so the denylist sees the
/// canonical actor URL (matching what M4 Stage 4.1 publishes), not the
/// pre-resolution handle.
///
/// Returns the resolved [`Url`] so the caller can immediately hand it
/// to `FediverseTransport::deliver` without re-resolving.
///
/// # Errors
/// - [`ChatError::Invalid`] when the mention is malformed or
///   `WebFinger` resolution fails (DNS / HTTP / JRD parse). The
///   inner [`fetchit_fedi::WebFingerError`] message rides in the `String` payload.
/// - [`ChatError::DeniedActor`] when the resolved actor URL is on
///   the community denylist.
pub async fn check_mention_denylist(
    denylist: &dyn DenylistCheck,
    mention: &str,
) -> Result<Url, ChatError> {
    let parsed =
        parse_mention(mention).map_err(|e| ChatError::Invalid(format!("webfinger: {e}")))?;
    // V-2/V-5 fold: resolve_handle now owns its `reqwest::Client`
    // construction (Policy::none + resolved-addrs pin), so callers
    // no longer hand in a possibly-misconfigured client.
    let actor_url = resolve_handle(&parsed)
        .await
        .map_err(|e| ChatError::Invalid(format!("webfinger: {e}")))?;
    check_actor_url_denylist(denylist, actor_url.as_str()).await?;
    Ok(actor_url)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub(crate) mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::HashSet;
    use std::sync::Mutex;

    /// Actor-URL denylist stub. Shared with the other modules whose
    /// gates run over actor URLs (the read feed) so they all pin the
    /// same canonical-form matching behaviour.
    pub(crate) struct StubDenylist {
        actor_urls: Mutex<HashSet<String>>,
    }

    impl StubDenylist {
        pub(crate) fn new<I, S>(blocked: I) -> Self
        where
            I: IntoIterator<Item = S>,
            S: Into<String>,
        {
            Self {
                actor_urls: Mutex::new(blocked.into_iter().map(Into::into).collect()),
            }
        }
    }

    #[async_trait]
    impl DenylistCheck for StubDenylist {
        async fn is_blocked(&self, _agent_id_hex: &str) -> bool {
            false
        }
        async fn is_blocked_actor(&self, actor_url: &str) -> bool {
            self.actor_urls.lock().unwrap().contains(actor_url)
        }
    }

    fn post_with_reply_to(reply_to: Option<&str>) -> PublicPost {
        PublicPost {
            author_handle: "@josh@etchit.io".to_owned(),
            body_md: "body".to_owned(),
            created_at_ms: 0,
            reply_to_actor_url: reply_to.map(str::to_owned),
            reply_to_object_url: None,
            mentions: vec!["@eve@attacker.example".to_owned()],
        }
    }

    #[tokio::test]
    async fn check_actor_url_blocked_returns_denied_actor_with_url() {
        let d = StubDenylist::new(["https://attacker.example/users/eve"]);
        let err = check_actor_url_denylist(&d, "https://attacker.example/users/eve")
            .await
            .unwrap_err();
        match err {
            ChatError::DeniedActor { actor_url } => {
                assert_eq!(actor_url, "https://attacker.example/users/eve");
            }
            other => panic!("expected DeniedActor, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_actor_url_unblocked_passes() {
        let d = StubDenylist::new(["https://attacker.example/users/eve"]);
        check_actor_url_denylist(&d, "https://mastodon.example/users/alice")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn trailing_slash_variant_cannot_evade_the_denylist() {
        // Cross-review round 2: the consumer index matches exact
        // canonical form, so the gate must canonicalize the remote's
        // self-served id before the lookup.
        let d = StubDenylist::new(["https://attacker.example/users/eve"]);
        assert!(
            check_actor_url_denylist(&d, "https://attacker.example/users/eve/")
                .await
                .is_err(),
            "a trailing slash must not bypass the blocklist"
        );
    }

    #[tokio::test]
    async fn degenerate_actor_ids_fail_closed() {
        // No legitimate ActivityPub actor id carries a query, fragment,
        // or userinfo — a gate against hostile actors denies them
        // outright rather than passing an uncanonicalizable value to an
        // exact-match index.
        let d = StubDenylist::new(["https://attacker.example/users/eve"]);
        for degenerate in [
            "https://attacker.example/users/eve?x=1",
            "https://attacker.example/users/eve#frag",
            "https://user@attacker.example/users/eve",
        ] {
            assert!(
                check_actor_url_denylist(&d, degenerate).await.is_err(),
                "{degenerate} must fail closed"
            );
        }
    }

    #[tokio::test]
    async fn optional_gate_passes_when_no_denylist_is_installed() {
        // Fail-open is the not-installed contract: a client with no
        // consumer wired must still reach every actor.
        check_optional_actor_url_denylist(None, "https://attacker.example/users/eve")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn optional_gate_blocks_through_a_wired_denylist() {
        let d = StubDenylist::new(["https://attacker.example/users/eve"]);
        assert!(
            check_optional_actor_url_denylist(Some(&d), "https://attacker.example/users/eve")
                .await
                .is_err()
        );
        check_optional_actor_url_denylist(Some(&d), "https://mastodon.example/users/alice")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn optional_gate_keeps_the_canonicalizing_and_fail_closed_rules() {
        let d = StubDenylist::new(["https://attacker.example/users/eve"]);
        assert!(
            check_optional_actor_url_denylist(Some(&d), "https://attacker.example/users/eve/")
                .await
                .is_err(),
            "a trailing slash must not bypass the blocklist",
        );
        assert!(
            check_optional_actor_url_denylist(Some(&d), "https://attacker.example/users/eve?x=1")
                .await
                .is_err(),
            "degenerate ids fail closed",
        );
    }

    #[tokio::test]
    async fn check_publish_blocked_reply_to_surfaces_url() {
        let d = StubDenylist::new(["https://attacker.example/users/eve"]);
        let post = post_with_reply_to(Some("https://attacker.example/users/eve"));
        let err = check_publish_denylist(&d, &post).await.unwrap_err();
        assert!(matches!(
            err,
            ChatError::DeniedActor { ref actor_url }
                if actor_url == "https://attacker.example/users/eve"
        ));
    }

    #[tokio::test]
    async fn check_publish_no_reply_to_passes_even_with_blocked_mentions() {
        // Mention handles are NOT gated at this stage; Stage 5.2 wires
        // the per-mention gate after WebFinger resolution. This test
        // pins that contract so a future change to gate mentions here
        // is a conscious decision, not silent drift.
        let d = StubDenylist::new(["@eve@attacker.example"]);
        let post = post_with_reply_to(None);
        check_publish_denylist(&d, &post).await.unwrap();
    }

    #[tokio::test]
    async fn check_publish_unblocked_reply_to_passes() {
        let d = StubDenylist::new(["https://attacker.example/users/eve"]);
        let post = post_with_reply_to(Some("https://mastodon.example/users/alice"));
        check_publish_denylist(&d, &post).await.unwrap();
    }

    #[tokio::test]
    async fn check_mention_malformed_returns_invalid() {
        let d = StubDenylist::new(Vec::<String>::new());
        let err = check_mention_denylist(&d, "not-a-handle")
            .await
            .unwrap_err();
        match err {
            ChatError::Invalid(msg) => assert!(
                msg.contains("webfinger") && msg.contains("malformed"),
                "expected wrapped malformed-handle error, got: {msg}",
            ),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_mention_unreachable_instance_returns_invalid() {
        // resolve_handle owns its reqwest::Client (V-2/V-5 fold), so
        // the test no longer threads a tuned client — the unreachable
        // instance still surfaces as a wrapped Invalid via lookup_host
        // failure or transport timeout on the owned client.
        let d = StubDenylist::new(Vec::<String>::new());
        let err = check_mention_denylist(&d, "@alice@nx-mastodon-empirical.invalid")
            .await
            .unwrap_err();
        match err {
            ChatError::Invalid(msg) => assert!(
                msg.contains("webfinger"),
                "expected wrapped transport error, got: {msg}",
            ),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }
}
