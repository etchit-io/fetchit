//! Device-side driver for the user's OWN profile picture.
//!
//! The write half of the avatar story ([`crate::fedi_avatar`] is the
//! read half). Setting a picture is four steps, in this order:
//!
//! 1. upload the bytes to our own bridge under `bridge-auth-v1`;
//! 2. record the resulting `icon` URL in the actor vault;
//! 3. re-register the actor document, so the fediverse sees the `icon`;
//! 4. write the bytes into the pinned self slot of the avatar cache.
//!
//! Step 4 is what lets the LIT chat header draw the user's face without
//! any surface issuing a request — the bytes never have to come back
//! over HTTP because they started here.
//!
//! The order matters at both ends. On set, the upload comes first: an
//! `icon` URL published before the bytes exist is a broken image on
//! every timeline that renders it. On clear, the doc is re-registered
//! after the delete for the same reason in reverse.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use fetchit_fedi::avatar::{
    magic_matches_content_type, normalize_content_type, MAX_AVATAR_BYTES,
    UPLOADABLE_AVATAR_CONTENT_TYPES,
};
use fetchit_fedi::bridge_auth::{canonical_request, HEADER_AGENT, HEADER_SIG, HEADER_TS};

use crate::client::Client;
use crate::error::{ChatError, Result};
use crate::fedi_follow::actor_origin;

/// The avatar-cache label for our own actor.
///
/// Identical in shape to every correspondent's label (`user@host`), so
/// the self slot rides the ordinary cache read path — and identical to
/// what [`crate::fedi_feed::author_label`] derives from our actor URL,
/// which is how a shell that only knows `handle` + domain can address
/// it.
#[must_use]
pub fn self_avatar_label(handle: &str, domain: &str) -> String {
    format!("{handle}@{domain}")
}

/// Pre-flight an outgoing picture: exactly the checks the bridge will
/// run, run here first so a bad one never leaves the device (and a
/// would-be 415 costs no round trip). Returns the normalised content
/// type to send.
///
/// # Errors
/// [`ChatError::Invalid`] naming the failed check, in words a shell can
/// show the user unchanged.
fn validate_avatar(bytes: &[u8], content_type: &str) -> Result<String> {
    let content_type = normalize_content_type(content_type);
    if !UPLOADABLE_AVATAR_CONTENT_TYPES.contains(&content_type.as_str()) {
        return Err(ChatError::Invalid(format!(
            "unsupported picture format {content_type:?}"
        )));
    }
    if bytes.is_empty() {
        return Err(ChatError::Invalid("picture is empty".into()));
    }
    if bytes.len() > MAX_AVATAR_BYTES {
        return Err(ChatError::Invalid(format!(
            "picture is {} bytes; the limit is {MAX_AVATAR_BYTES}",
            bytes.len()
        )));
    }
    if !magic_matches_content_type(&content_type, bytes) {
        return Err(ChatError::Invalid(
            "picture bytes do not match their declared format".into(),
        ));
    }
    Ok(content_type)
}

impl Client {
    /// Set the user's profile picture: host the bytes on our bridge,
    /// publish the `icon` on the actor document, and pin them into the
    /// local self slot.
    ///
    /// `bytes` are stored and served verbatim — the shell has already
    /// re-encoded the user's photo (which is what strips its EXIF), and
    /// nothing in the engine or the bridge decodes an image.
    ///
    /// # Errors
    /// [`ChatError::Invalid`] when no identity is minted for `handle`,
    /// the image fails the pre-flight (type, magic, size), the bridge
    /// rejects the upload, or the vault cannot be written. A failed
    /// upload leaves the published `icon` untouched, so the previous
    /// picture keeps rendering.
    pub async fn set_fedi_avatar(
        &self,
        handle: &str,
        bytes: Vec<u8>,
        content_type: &str,
        now_ms: u64,
    ) -> Result<String> {
        let content_type = validate_avatar(&bytes, content_type)?;
        let identity = self.require_actor_identity(handle).await?;
        let origin = actor_origin(&identity)?;
        let icon_url = format!("{origin}/actors/{handle}/avatar");

        self.upload_avatar_to_bridge(handle, &origin, &bytes, &content_type, now_ms)
            .await?;
        let identity = self
            .record_actor_icon(handle, Some(icon_url.clone()), Some(content_type.clone()))
            .await?;
        self.reregister_actor(&origin, &identity).await;

        // Pin the bytes we just uploaded. Best-effort: the picture is
        // live on the fediverse either way, and a cache write failure
        // must not read back as "setting your picture failed".
        if let Some(layout) = self.layout() {
            let label = crate::fedi_feed::author_label(identity.actor_url.as_str());
            if let Err(e) = crate::fedi_avatar::store_own(
                layout,
                &label,
                &icon_url,
                &bytes,
                &content_type,
                i64::try_from(now_ms).unwrap_or(i64::MAX),
            ) {
                log::debug!("[fedi] self-avatar cache write failed: {e}");
            }
        }
        Ok(icon_url)
    }

    /// Remove the user's profile picture: delete the hosted bytes, drop
    /// the `icon` from the actor document, and clear the self slot.
    ///
    /// # Errors
    /// [`ChatError::Invalid`] when no identity is minted for `handle`,
    /// the bridge refuses the delete, or the vault cannot be written.
    pub async fn clear_fedi_avatar(&self, handle: &str, now_ms: u64) -> Result<()> {
        let identity = self.require_actor_identity(handle).await?;
        let origin = actor_origin(&identity)?;
        let path = format!("/actors/{handle}/avatar");
        let canonical = canonical_request("DELETE", &path, now_ms, b"");
        let (agent_id_hex, sig) = self.bridge_auth_sign(&canonical).await?;
        let resp = crate::relay_http::guarded_client()
            .delete(format!("{origin}{path}"))
            .header(HEADER_AGENT, agent_id_hex)
            .header(HEADER_TS, now_ms.to_string())
            .header(HEADER_SIG, B64.encode(&sig))
            .send()
            .await
            .map_err(|e| ChatError::Invalid(format!("bridge avatar DELETE: {e}")))?;
        if !resp.status().is_success() {
            return Err(ChatError::Invalid(format!(
                "bridge refused the removal: HTTP {}",
                resp.status().as_u16()
            )));
        }

        let identity = self.record_actor_icon(handle, None, None).await?;
        self.reregister_actor(&origin, &identity).await;
        if let Some(layout) = self.layout() {
            let label = crate::fedi_feed::author_label(identity.actor_url.as_str());
            if let Err(e) = crate::fedi_avatar::forget(layout, &label) {
                log::debug!("[fedi] self-avatar cache clear failed: {e}");
            }
        }
        Ok(())
    }

    /// The user's own picture, read from the pinned self slot. Cache
    /// only: no fetch, no cadence, no backoff — the LIT chat header
    /// draws this, and that surface may never produce a request.
    #[must_use]
    pub fn fedi_self_avatar(&self, handle: &str, domain: &str) -> Option<Vec<u8>> {
        self.fedi_avatar_cached(&self_avatar_label(handle, domain))
    }

    async fn require_actor_identity(
        &self,
        handle: &str,
    ) -> Result<fetchit_fedi::actor::ActorIdentity> {
        self.load_actor_identity(handle).await?.ok_or_else(|| {
            ChatError::Invalid(format!(
                "no fediverse actor identity minted for handle {handle}"
            ))
        })
    }

    async fn upload_avatar_to_bridge(
        &self,
        handle: &str,
        origin: &str,
        bytes: &[u8],
        content_type: &str,
        now_ms: u64,
    ) -> Result<()> {
        let path = format!("/actors/{handle}/avatar");
        let canonical = canonical_request("POST", &path, now_ms, bytes);
        let (agent_id_hex, sig) = self.bridge_auth_sign(&canonical).await?;
        let resp = crate::relay_http::guarded_client()
            .post(format!("{origin}{path}"))
            .header(HEADER_AGENT, agent_id_hex)
            .header(HEADER_TS, now_ms.to_string())
            .header(HEADER_SIG, B64.encode(&sig))
            .header("content-type", content_type)
            .body(bytes.to_vec())
            .send()
            .await
            .map_err(|e| ChatError::Invalid(format!("bridge avatar POST: {e}")))?;
        if resp.status().is_success() {
            return Ok(());
        }
        Err(ChatError::Invalid(format!(
            "bridge refused the picture: HTTP {}",
            resp.status().as_u16()
        )))
    }

    /// Re-assert the actor document so the published `icon` matches the
    /// vault. Best-effort by design: the bytes are already hosted (or
    /// already gone), and a bridge blip must not fail the user's action
    /// — the next ensure pass re-registers anyway.
    async fn reregister_actor(&self, origin: &str, identity: &fetchit_fedi::actor::ActorIdentity) {
        let Ok(base) = format!("{origin}/").parse::<url::Url>() else {
            return;
        };
        let http = crate::relay_http::guarded_client();
        let state = crate::fedi_identity::register_or_update_actor(&base, identity, &http).await;
        if let Some(reason) = state.error_text() {
            log::warn!("[fedi] avatar re-registration deferred: {reason}");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A minimal-but-real JPEG head, so the magic pre-flight passes.
    fn jpeg(len: usize) -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0];
        v.resize(len.max(4), 0x42);
        v
    }

    #[test]
    fn the_self_slot_label_is_the_one_the_cache_derives_from_our_actor_url() {
        // The shell addresses the self slot from `handle` + domain; the
        // set path writes it from the actor URL. Those two have to be
        // the same string or the badge reads an empty slot forever.
        let actor_url = "https://etchit.io/actors/josh";
        assert_eq!(
            self_avatar_label("josh", "etchit.io"),
            crate::fedi_feed::author_label(actor_url)
        );
        assert_eq!(self_avatar_label("josh", "etchit.io"), "josh@etchit.io");
    }

    #[test]
    fn the_published_icon_url_matches_what_the_bridge_serves() {
        // The client publishes this URL; the bridge routes
        // /actors/:handle/avatar. A drift here is a broken image on
        // every timeline that renders the account.
        let origin = "https://etchit.io";
        let handle = "josh";
        assert_eq!(
            format!("{origin}/actors/{handle}/avatar"),
            "https://etchit.io/actors/josh/avatar"
        );
    }

    fn err_of(bytes: &[u8], content_type: &str) -> String {
        format!(
            "{}",
            validate_avatar(bytes, content_type).expect_err("must be rejected")
        )
    }

    #[test]
    fn a_valid_picture_passes_and_normalises_its_type() {
        // The negative cases below only mean something if a GOOD image
        // gets through rather than tripping some other gate.
        assert_eq!(
            validate_avatar(&jpeg(64), "Image/JPEG; charset=binary").unwrap(),
            "image/jpeg"
        );
        // The cap is inclusive, matching the bridge's body limit.
        assert!(validate_avatar(&jpeg(MAX_AVATAR_BYTES), "image/jpeg").is_ok());
    }

    #[test]
    fn a_picture_that_is_not_an_allowed_image_is_refused_locally() {
        for ct in ["image/gif", "image/svg+xml", "text/html", ""] {
            let msg = err_of(&jpeg(16), ct);
            assert!(
                msg.contains("unsupported picture format"),
                "{ct} must be refused: {msg}"
            );
        }
    }

    #[test]
    fn an_empty_or_oversized_picture_is_refused_locally() {
        assert!(err_of(&[], "image/jpeg").contains("picture is empty"));
        let msg = err_of(&jpeg(MAX_AVATAR_BYTES + 1), "image/jpeg");
        assert!(msg.contains("the limit is"), "{msg}");
    }

    #[test]
    fn bytes_that_do_not_match_their_declared_format_are_refused_locally() {
        // The same check the bridge runs, run first so a mislabelled
        // file never leaves the device at all.
        let msg = err_of(b"<!doctype html><script>", "image/png");
        assert!(msg.contains("do not match their declared format"), "{msg}");
    }
}
