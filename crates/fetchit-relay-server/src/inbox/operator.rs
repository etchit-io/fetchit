//! M4 Stage 7 — operator opt-in wiring that turns a relay into a
//! production fediverse inbox.
//!
//! The inbox traits ([`InboxDenylistCheck`], [`WebFingerLookup`]) are
//! injected so the gate pipeline stays testable with stubs. This module
//! supplies the PRODUCTION impls — both reuse existing crate code rather
//! than re-implementing HTTP or crypto:
//!
//! - [`DenylistConsumerCheck`] wraps `fetchit_trust_client::DenylistConsumer`
//!   (the same signed `etchit-io` denylist desktop clients consult) and
//!   gates an actor URL through `EntryKind::ActorUrl`.
//! - [`FediverseWebFinger`] resolves an HTTP-Signature `keyId` to the
//!   signer's RSA public-key PEM by fetching the actor document via
//!   `fetchit_fedi::actor::fetch_actor` (SSRF-gated) and caching the PEM
//!   with a TTL.
//!
//! [`attach_if_enabled`] reads the operator opt-in from the environment
//! and, when set, assembles these with the [`SessionBroadcastSink`] and
//! mounts the inbox via [`crate::server::Server::with_inbox`].

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::RwLock;

use super::{
    InboxDenylistCheck, InboxState, PendingDeliverySink, SessionBroadcastSink, WebFingerError,
    WebFingerLookup,
};
use crate::server::Server;

/// Default signed-denylist base URL — the live NY-Trust service. Matches
/// the desktop client's `DEFAULT_DENYLIST_URL`; override with
/// `FETCHIT_DENYLIST_URL`.
const DEFAULT_DENYLIST_URL: &str = "https://trust.etchit.io/v1";

/// Default TTL for cached actor public keys (24h), matching the
/// HTTP-Signature capability cache.
const PUBKEY_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// `true` when the operator opted this relay into the fediverse-inbox
/// role via `FETCHIT_FEDIVERSE_INBOX=1` (or `true`).
#[must_use]
pub fn fediverse_inbox_enabled() -> bool {
    matches!(
        std::env::var("FETCHIT_FEDIVERSE_INBOX").as_deref(),
        Ok("1" | "true" | "TRUE")
    )
}

/// Production [`InboxDenylistCheck`] backed by the signed `etchit-io`
/// denylist (`fetchit_trust_client::DenylistConsumer`).
pub struct DenylistConsumerCheck {
    consumer: Arc<fetchit_trust_client::DenylistConsumer>,
}

impl DenylistConsumerCheck {
    /// Wrap `consumer` and spawn its background poll loop, refreshing the
    /// signed denylist through `http` (production: `ReqwestClient`). The
    /// poll task is detached — it holds its own `Arc` clone of the
    /// consumer, so it runs for the life of the process. Must be called
    /// inside a Tokio runtime.
    #[must_use]
    pub fn new(
        consumer: Arc<fetchit_trust_client::DenylistConsumer>,
        http: Arc<dyn fetchit_trust_client::HttpClient + Send + Sync + 'static>,
    ) -> Self {
        let _poll = Arc::clone(&consumer).spawn_poll_loop(http);
        Self { consumer }
    }
}

#[async_trait]
impl InboxDenylistCheck for DenylistConsumerCheck {
    async fn is_blocked_actor(&self, actor_url: &str) -> bool {
        self.consumer
            .is_blocked(fetchit_trust_client::EntryKind::ActorUrl, actor_url)
    }
}

/// Production [`WebFingerLookup`] — resolves an HTTP-Signature `keyId`
/// to the signer's RSA public-key PEM and caches it with a TTL.
pub struct FediverseWebFinger {
    cache: RwLock<HashMap<String, CacheEntry>>,
    ttl: Duration,
}

struct CacheEntry {
    pem: String,
    fetched_at: Instant,
}

impl Default for FediverseWebFinger {
    fn default() -> Self {
        Self::new()
    }
}

impl FediverseWebFinger {
    /// New resolver with the default [`PUBKEY_CACHE_TTL`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            ttl: PUBKEY_CACHE_TTL,
        }
    }

    async fn cached(&self, key_id: &str) -> Option<String> {
        let guard = self.cache.read().await;
        let entry = guard.get(key_id)?;
        (entry.fetched_at.elapsed() < self.ttl).then(|| entry.pem.clone())
    }

    async fn store(&self, key_id: &str, pem: String) {
        self.cache.write().await.insert(
            key_id.to_owned(),
            CacheEntry {
                pem,
                fetched_at: Instant::now(),
            },
        );
    }
}

/// Strip the fragment from a `keyId` (e.g. `…/actor#main-key`) to recover
/// the actor document URL `fetch_actor` should pull.
fn key_id_to_actor_url(key_id: &str) -> Result<url::Url, WebFingerError> {
    let mut url = url::Url::parse(key_id)
        .map_err(|e| WebFingerError::Malformed(format!("keyId is not a URL: {e}")))?;
    url.set_fragment(None);
    Ok(url)
}

#[async_trait]
impl WebFingerLookup for FediverseWebFinger {
    async fn resolve_pubkey_pem(&self, key_id: &str) -> Result<String, WebFingerError> {
        if let Some(pem) = self.cached(key_id).await {
            return Ok(pem);
        }
        let actor_url = key_id_to_actor_url(key_id)?;
        // `fetch_actor` owns its SSRF-gated client (private-IP reject +
        // address pinning); every failure mode collapses to the inbox's
        // single `webfinger_lookup_failed` drop reason, so the umbrella
        // mapping loses nothing the gate distinguishes.
        let actor = fetchit_fedi::actor::fetch_actor(&actor_url)
            .await
            .map_err(|e| WebFingerError::Network(e.to_string()))?;
        let pem = actor.rsa_public_key_pem;
        self.store(key_id, pem.clone()).await;
        Ok(pem)
    }

    async fn invalidate(&self, key_id: &str) {
        self.cache.write().await.remove(key_id);
    }
}

/// Assemble + mount the production fediverse inbox when the operator
/// opted in (`FETCHIT_FEDIVERSE_INBOX`). A no-op returning `server`
/// unchanged otherwise, so a default community relay never serves
/// `/inbox`.
///
/// Reads `FETCHIT_DENYLIST_URL` (default [`DEFAULT_DENYLIST_URL`]) and
/// optional `FETCHIT_DENYLIST_CACHE` for the on-disk snapshot. The sink
/// is wired to the server's OWN [`crate::session::SessionRegistry`] (via
/// [`Server::sessions`]) so a broadcast `PublicPost` reaches live WS
/// sessions. Must be called inside a Tokio runtime (spawns the denylist
/// poll loop).
///
/// # Errors
/// Returns an error only if the production HTTP client cannot be built.
pub fn attach_if_enabled(server: Server) -> anyhow::Result<Server> {
    if !fediverse_inbox_enabled() {
        return Ok(server);
    }

    let denylist_url =
        std::env::var("FETCHIT_DENYLIST_URL").unwrap_or_else(|_| DEFAULT_DENYLIST_URL.to_owned());
    let cache_path = std::env::var("FETCHIT_DENYLIST_CACHE")
        .ok()
        .map(PathBuf::from);

    let consumer = Arc::new(fetchit_trust_client::DenylistConsumer::new(
        fetchit_trust_client::etchitio_pubkey(),
        denylist_url,
        cache_path,
    ));
    let http: Arc<dyn fetchit_trust_client::HttpClient + Send + Sync + 'static> =
        Arc::new(fetchit_trust_client::ReqwestClient::new()?);

    let denylist: Arc<dyn InboxDenylistCheck> =
        Arc::new(DenylistConsumerCheck::new(consumer, http));
    let webfinger: Arc<dyn WebFingerLookup> = Arc::new(FediverseWebFinger::new());
    let sink: Arc<dyn PendingDeliverySink> = Arc::new(SessionBroadcastSink::new(server.sessions()));

    let state = InboxState::builder(denylist, webfinger, sink).build();
    tracing::info!("fediverse inbox enabled: POST /inbox mounted");
    Ok(server.with_inbox(state))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn key_id_to_actor_url_strips_fragment() {
        let url = key_id_to_actor_url("https://mastodon.example/users/alice#main-key").unwrap();
        assert_eq!(url.as_str(), "https://mastodon.example/users/alice");
        assert!(url.fragment().is_none());
    }

    #[test]
    fn key_id_to_actor_url_rejects_non_url() {
        assert!(key_id_to_actor_url("not a url").is_err());
    }

    #[tokio::test]
    async fn webfinger_cache_stores_returns_and_invalidates() {
        let wf = FediverseWebFinger::new();
        let key_id = "https://mastodon.example/users/alice#main-key";
        assert!(wf.cached(key_id).await.is_none(), "empty cache misses");

        wf.store(key_id, "-----BEGIN PUBLIC KEY-----".to_owned())
            .await;
        assert_eq!(
            wf.cached(key_id).await.as_deref(),
            Some("-----BEGIN PUBLIC KEY-----"),
            "stored PEM is served from cache"
        );

        wf.invalidate(key_id).await;
        assert!(
            wf.cached(key_id).await.is_none(),
            "invalidate forces a re-fetch"
        );
    }

    #[tokio::test]
    async fn webfinger_cache_expires_past_ttl() {
        // Zero TTL: a stored entry is immediately stale, so the resolver
        // would re-fetch rather than serve a cached pubkey.
        let wf = FediverseWebFinger {
            cache: RwLock::new(HashMap::new()),
            ttl: Duration::from_secs(0),
        };
        wf.store("k", "pem".to_owned()).await;
        assert!(wf.cached("k").await.is_none(), "zero-TTL entry is stale");
    }

    /// Never-returning HTTP stub: the denylist poll loop's first tick
    /// fires after the (minutes-long) poll interval, so during the test
    /// it never runs — the stub just satisfies the type.
    struct PendingHttp;
    #[async_trait]
    impl fetchit_trust_client::HttpClient for PendingHttp {
        async fn get(
            &self,
            _url: &str,
        ) -> std::result::Result<Vec<u8>, fetchit_trust_client::TrustError> {
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn denylist_check_delegates_to_consumer_and_defaults_unblocked() {
        let consumer = Arc::new(fetchit_trust_client::DenylistConsumer::new(
            fetchit_trust_client::etchitio_pubkey(),
            "https://trust.example/v1".to_owned(),
            None,
        ));
        let check = DenylistConsumerCheck::new(consumer, Arc::new(PendingHttp));
        // No manifest has refreshed, so the index is empty: an actor is
        // not blocked (fail-open until the first signed refresh lands,
        // matching the desktop consumer's semantics).
        assert!(
            !check
                .is_blocked_actor("https://mastodon.example/users/alice")
                .await
        );
    }
}
