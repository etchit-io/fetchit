//! C=Public chat-layer surface — denylist gating helpers for the
//! Stage 5 fediverse publish path.
//!
//! Stage 5.1-chat exposes the gating primitives only;
//! `Client::publish_public_post` lands in Stage 5.2 and consumes
//! them. Splitting the gate from the publish-driver keeps the
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
use fetchit_fedi::PublicPost;

/// Single-shot denylist check against one canonical-form actor URL.
///
/// Returns [`ChatError::DeniedActor`] when the URL is blocked,
/// `Ok(())` when not. Cheap (one trait-method call); intended for
/// per-mention gating from Stage 5.2 after `WebFinger` resolution.
///
/// # Errors
/// Surfaces [`ChatError::DeniedActor`] when `actor_url` is on the
/// community denylist.
pub async fn check_actor_url_denylist(
    denylist: &dyn DenylistCheck,
    actor_url: &str,
) -> Result<(), ChatError> {
    if denylist.is_blocked_actor(actor_url).await {
        return Err(ChatError::DeniedActor {
            actor_url: actor_url.to_owned(),
        });
    }
    Ok(())
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::HashSet;
    use std::sync::Mutex;

    struct StubDenylist {
        actor_urls: Mutex<HashSet<String>>,
    }

    impl StubDenylist {
        fn new<I, S>(blocked: I) -> Self
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
}
