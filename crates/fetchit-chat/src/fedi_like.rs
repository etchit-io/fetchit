//! Device-side fediverse like / unlike driver plus its durable
//! liked-set (M7).
//!
//! The bridge holds no keys, so favouriting a post is a device
//! operation: resolve the post's author (SSRF-guarded, denylist-gated),
//! sign a `Like` with our actor's RSA key, and deliver it to their
//! inbox — the same twelve-line shape [`Client::follow_fedi`] uses.
//!
//! Which posts we like is ALSO device state. There is no cheap
//! `ActivityPub` source for "did I like this" (the author's `likes`
//! collection is usually counts-only, and walking it per feed row would
//! be one request per post), so the liked-set is persisted here and
//! joined against the feed when it is built. v1 renders liked-state
//! only — never a like COUNT, which would need that same missing
//! source and would be a number we could not honestly stand behind.
//!
//! Same seal shape as [`crate::fedi_thread`] (magic ‖ nonce ‖ AEAD
//! ciphertext) under the same HKDF-derived key, with distinct magic +
//! AAD so a blob swapped between the two stores fails the tag check.

use crate::at_rest::MasterKey;
use crate::client::Client;
use crate::error::{ChatError, Result};
use crate::fedi_identity::derive_fedi_vault_key;
use crate::fedi_vault::{read_sealed, write_sealed_atomic};
use crate::local_store::StoreLayout;
use fetchit_fedi::activity::{build_like, build_undo_like};
use fetchit_fedi::signature::HttpSignatureKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// File magic identifying a Fetchit Fedi Likes v1 file.
pub const FEDI_LIKES_MAGIC: &[u8; 4] = b"FFL1";

/// AAD bound into every seal/open — domain-separated from
/// [`crate::fedi_thread::FEDI_THREADS_AAD`] under the shared key.
pub const FEDI_LIKES_AAD: &[u8] = b"fetchit-fedi-likes-v1";

/// Liked posts retained. Past this the oldest likes are forgotten
/// (the heart empties on a post from years ago) rather than letting an
/// append-only set grow without bound on a long-lived device.
pub const MAX_LIKED_POSTS: usize = 2000;

/// Which posts this device has liked, keyed by post (`object`) URL.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FediLikes {
    /// Post URL → epoch-ms stamp of the like. The stamp is the eviction
    /// order, nothing else reads it.
    #[serde(default)]
    pub liked: BTreeMap<String, i64>,
}

impl FediLikes {
    /// Whether `object_url` is liked on this device.
    #[must_use]
    pub fn is_liked(&self, object_url: &str) -> bool {
        self.liked.contains_key(object_url)
    }

    /// Record a like of `object_url`, evicting oldest-first past
    /// [`MAX_LIKED_POSTS`]. Returns `false` when it was already liked
    /// (the caller can then skip the re-seal).
    pub fn like(&mut self, object_url: &str, now_ms: i64) -> bool {
        if self.liked.insert(object_url.to_owned(), now_ms).is_some() {
            return false;
        }
        self.evict();
        true
    }

    /// Drop the like on `object_url`. Returns `false` when it was not
    /// liked.
    pub fn unlike(&mut self, object_url: &str) -> bool {
        self.liked.remove(object_url).is_some()
    }

    /// Every liked post URL. The join key when a feed is built.
    #[must_use]
    pub fn liked_urls(&self) -> Vec<String> {
        self.liked.keys().cloned().collect()
    }

    fn evict(&mut self) {
        while self.liked.len() > MAX_LIKED_POSTS {
            // Oldest stamp goes; the URL breaks ties so eviction is
            // deterministic rather than dependent on map iteration luck.
            let Some(oldest) = self
                .liked
                .iter()
                .min_by(|a, b| a.1.cmp(b.1).then_with(|| a.0.cmp(b.0)))
                .map(|(k, _)| k.clone())
            else {
                return;
            };
            self.liked.remove(&oldest);
        }
    }
}

/// Load the liked-set for `handle`. A missing file is a fresh, empty
/// set; a present-but-unreadable file is an error so likes are never
/// silently dropped.
///
/// # Errors
/// [`ChatError`] on IO, seal, or JSON-decode failures.
pub fn load_fedi_likes(
    handle: &str,
    master: &MasterKey,
    layout: &StoreLayout,
) -> Result<FediLikes> {
    let key = derive_fedi_vault_key(master);
    let path = layout.fedi_likes_path(handle);
    let Some(plain) = read_sealed(&path, *FEDI_LIKES_MAGIC, &key, FEDI_LIKES_AAD)? else {
        return Ok(FediLikes::default());
    };
    serde_json::from_slice(&plain)
        .map_err(|e| ChatError::Invalid(format!("fedi likes decode: {e}")))
}

/// Seal and atomically persist the liked-set for `handle`.
///
/// # Errors
/// [`ChatError`] on JSON-encode, IO, or seal failures.
pub fn save_fedi_likes(
    handle: &str,
    likes: &FediLikes,
    master: &MasterKey,
    layout: &StoreLayout,
) -> Result<()> {
    let key = derive_fedi_vault_key(master);
    let plain = serde_json::to_vec(likes)
        .map_err(|e| ChatError::Invalid(format!("fedi likes encode: {e}")))?;
    write_sealed_atomic(
        &layout.fedi_likes_path(handle),
        *FEDI_LIKES_MAGIC,
        &key,
        FEDI_LIKES_AAD,
        &plain,
    )
}

/// Outcome of a like / unlike: the local state always moved, delivery
/// is best-effort.
#[derive(Clone, Copy, Debug)]
pub struct LikeReport {
    /// The author's inbox accepted the activity. A `false` means the
    /// local state still flipped — a transient inbox outage must not
    /// lose the user's intent, and the activity id is derived from the
    /// post URL so a later re-send is idempotent remotely.
    pub delivered: bool,
    /// The durable liked-set actually changed. `false` for a re-like of
    /// something already liked (or an unlike of something that wasn't).
    pub changed: bool,
}

impl Client {
    /// Like the post at `object_url`, authored by `author_url`, from our
    /// actor `handle`: record it durably, then sign + deliver a `Like`
    /// to the author's inbox.
    ///
    /// # Errors
    /// [`ChatError::DeniedActor`] when the author is denylisted — a
    /// denied actor is gated BEFORE anything is recorded or sent, so a
    /// blocked account gets neither a local like nor a request.
    /// [`ChatError::Invalid`] for REST-only clients (no fedi transport /
    /// no minted actor) or a signing failure. A transient delivery
    /// failure is reported in [`LikeReport`], not errored.
    pub async fn like_fedi_post(
        &self,
        handle: &str,
        object_url: &str,
        author_url: &str,
        now_ms: u64,
    ) -> Result<LikeReport> {
        self.gate_actor_url(author_url).await?;
        let changed = self.set_liked(handle, object_url, true, now_ms)?;
        let identity = self.fedi_identity_for(handle).await?;
        let like = build_like(identity.actor_url.as_str(), object_url);
        let body = serde_json::to_vec(&like)
            .map_err(|e| ChatError::Invalid(format!("serialize Like: {e}")))?;
        let delivered = self.deliver_to_author(&identity, author_url, &body).await;
        Ok(LikeReport { delivered, changed })
    }

    /// Undo a like of `object_url`: drop the durable record, then sign +
    /// deliver the `Undo(Like)` to `author_url`'s inbox.
    ///
    /// The `Like` being retracted is REBUILT from `object_url` rather
    /// than read back from the store — the activity id is a pure
    /// function of the post URL, so an unlike works even on a device
    /// that has forgotten (or never held) the original like.
    ///
    /// Deliberately NOT hard-gated on the denylist the way
    /// [`Self::like_fedi_post`] is: withdrawing an interaction must stay
    /// possible after the other party lands on the list. The local
    /// record always drops; the `Undo` is simply not delivered to a
    /// denied actor (`delivered: false`).
    ///
    /// # Errors
    /// [`ChatError::Invalid`] for REST-only clients (no fedi transport /
    /// no minted actor) or a signing failure.
    pub async fn unlike_fedi_post(
        &self,
        handle: &str,
        object_url: &str,
        author_url: &str,
        now_ms: u64,
    ) -> Result<LikeReport> {
        let changed = self.set_liked(handle, object_url, false, now_ms)?;
        let identity = self.fedi_identity_for(handle).await?;
        let like = build_like(identity.actor_url.as_str(), object_url);
        let undo = build_undo_like(identity.actor_url.as_str(), &like);
        let body = serde_json::to_vec(&undo)
            .map_err(|e| ChatError::Invalid(format!("serialize Undo(Like): {e}")))?;
        let delivered = self.deliver_to_author(&identity, author_url, &body).await;
        Ok(LikeReport { delivered, changed })
    }

    /// Every post URL `handle` has liked on this device — the join key
    /// the feed builder uses to stamp [`crate::fedi_feed::FediFeedPost::liked`].
    ///
    /// # Errors
    /// [`ChatError`] on store load failures.
    pub fn fedi_liked_posts(&self, handle: &str) -> Result<Vec<String>> {
        let (master, layout) = self.fedi_at_rest()?;
        Ok(load_fedi_likes(handle, &master, &layout)?.liked_urls())
    }

    /// Flip the durable liked-state for one post. Returns whether it
    /// moved; an unchanged state skips the re-seal.
    fn set_liked(&self, handle: &str, object_url: &str, liked: bool, now_ms: u64) -> Result<bool> {
        let (master, layout) = self.fedi_at_rest()?;
        let mut set = load_fedi_likes(handle, &master, &layout)?;
        let stamp = i64::try_from(now_ms).unwrap_or(i64::MAX);
        let moved = if liked {
            set.like(object_url, stamp)
        } else {
            set.unlike(object_url)
        };
        if moved {
            save_fedi_likes(handle, &set, &master, &layout)?;
        }
        Ok(moved)
    }

    /// The minted actor identity for `handle`, or a plain-language error.
    async fn fedi_identity_for(&self, handle: &str) -> Result<fetchit_fedi::actor::ActorIdentity> {
        self.load_actor_identity(handle).await?.ok_or_else(|| {
            ChatError::Invalid(format!(
                "no fediverse actor identity minted for handle {handle}"
            ))
        })
    }

    /// Resolve `author_url` (denylist-gated, SSRF-guarded) and POST
    /// `body` to their inbox under our actor's HTTP signature. Every
    /// failure is a `false`, never an error: the local state has
    /// already moved and a dead server must not undo the user's intent.
    async fn deliver_to_author(
        &self,
        identity: &fetchit_fedi::actor::ActorIdentity,
        author_url: &str,
        body: &[u8],
    ) -> bool {
        let Some(transport) = self.fediverse_transport() else {
            return false;
        };
        if self.gate_actor_url(author_url).await.is_err() {
            return false;
        }
        let Ok(url) = author_url.parse::<url::Url>() else {
            return false;
        };
        let Ok(author) = fetchit_fedi::lookup::fetch_remote_actor(&url).await else {
            return false;
        };
        self.note_fedi_avatar_source(
            &crate::fedi_feed::author_label(author.id.as_str()),
            author.icon_url.as_deref(),
        );
        let key = HttpSignatureKey {
            key_id: format!("{}#main-key", identity.actor_url),
            rsa_private_pem: identity.rsa_priv_pem.clone(),
        };
        transport
            .deliver(&key, body, &author.inbox, &identity.actor_url)
            .await
            .is_ok()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::chat_crypto::AEAD_KEY_LEN;
    use tempfile::tempdir;

    fn fixture_master(byte: u8) -> MasterKey {
        MasterKey::from_bytes_for_test([byte; AEAD_KEY_LEN])
    }

    fn layout() -> (StoreLayout, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        (layout, dir)
    }

    #[test]
    fn like_then_unlike_round_trips_the_flag() {
        let mut l = FediLikes::default();
        assert!(!l.is_liked("https://h/@a/1"));
        assert!(l.like("https://h/@a/1", 10), "first like moves the state");
        assert!(l.is_liked("https://h/@a/1"));
        assert!(!l.like("https://h/@a/1", 20), "re-like is a no-op");
        assert!(l.unlike("https://h/@a/1"));
        assert!(!l.is_liked("https://h/@a/1"));
        assert!(!l.unlike("https://h/@a/1"), "double unlike is a no-op");
    }

    #[test]
    fn the_liked_set_is_bounded_and_evicts_oldest_first() {
        let mut l = FediLikes::default();
        for i in 0..(MAX_LIKED_POSTS + 5) {
            l.like(&format!("https://h/@a/{i}"), i64::try_from(i).unwrap());
        }
        assert_eq!(l.liked.len(), MAX_LIKED_POSTS);
        for i in 0..5 {
            assert!(!l.is_liked(&format!("https://h/@a/{i}")), "oldest evicted");
        }
        assert!(l.is_liked(&format!("https://h/@a/{}", MAX_LIKED_POSTS + 4)));
    }

    #[test]
    fn likes_survive_the_seal_round_trip() {
        let (layout, _t) = layout();
        let master = fixture_master(0x51);
        let mut l = FediLikes::default();
        l.like("https://fosstodon.org/@happyborg/1", 100);
        save_fedi_likes("josh", &l, &master, &layout).unwrap();

        let back = load_fedi_likes("josh", &master, &layout).unwrap();
        assert!(back.is_liked("https://fosstodon.org/@happyborg/1"));
        assert_eq!(back.liked_urls().len(), 1);

        // On disk it is sealed, not plaintext JSON.
        let raw = std::fs::read(layout.fedi_likes_path("josh")).unwrap();
        assert_eq!(&raw[..4], FEDI_LIKES_MAGIC);
        assert!(!raw.windows(9).any(|w| w == b"happyborg"));
    }

    #[test]
    fn a_missing_file_loads_empty_but_a_wrong_key_errors() {
        let (layout, _t) = layout();
        assert!(load_fedi_likes("josh", &fixture_master(1), &layout)
            .unwrap()
            .liked
            .is_empty());

        let mut l = FediLikes::default();
        l.like("https://h/@a/1", 1);
        save_fedi_likes("josh", &l, &fixture_master(1), &layout).unwrap();
        assert!(
            load_fedi_likes("josh", &fixture_master(2), &layout).is_err(),
            "likes must never be silently clobbered",
        );
    }

    #[test]
    fn the_likes_store_is_invisible_to_actor_handle_enumeration() {
        // list_actor_handles scans fedi/*.json.enc; the likes store lives
        // one level down so it can never masquerade as a minted handle.
        let (layout, _t) = layout();
        save_fedi_likes("josh", &FediLikes::default(), &fixture_master(1), &layout).unwrap();
        assert!(crate::fedi_vault::list_actor_handles(&layout).is_empty());
    }

    #[test]
    fn a_store_written_before_likes_existed_decodes_as_empty() {
        // Forward-compat: `liked` is #[serde(default)], so an older blob
        // decodes rather than erroring.
        let l: FediLikes = serde_json::from_str("{}").unwrap();
        assert!(l.liked.is_empty());
    }
}
