//! Stage 2.1: multi-kind [`DenylistConsumer`] — coordinates HTTP
//! fetch, ML-DSA-65 signature verification, and the in-memory hot
//! lookup index across all four [`EntryKind`] variants.
//!
//! Reuses [`fetchit_trust::consumer::verify_signature`] for the
//! signature verify (no fresh ML-DSA code lives here) and the
//! crate-local [`DenylistIndexes`] for atomic per-kind index swaps.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use fetchit_trust::consumer::verify_signature;
use fetchit_trust::types::DenylistResponse;
use fetchit_trust::EntryKind;
use thiserror::Error;
use tokio::sync::broadcast;

use crate::http::HttpClient;
use crate::index::DenylistIndexes;

const ALL_KINDS: [EntryKind; 4] = [
    EntryKind::XorName,
    EntryKind::AgentId,
    EntryKind::RelayUrl,
    EntryKind::ActorUrl,
];

/// Default cadence for [`DenylistConsumer::spawn_poll_loop`]: 6 hours.
///
/// Production deployments may override via
/// [`DenylistConsumer::with_poll_interval`] for ops-tuning. Exposed
/// publicly so callers can construct a [`std::time::Duration`]
/// relative to it (e.g. `DEFAULT_POLL_INTERVAL / 3` for tests).
pub const DEFAULT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(6 * 60 * 60);

/// Errors produced by the trust-client crate.
#[derive(Debug, Error)]
pub enum TrustError {
    /// HTTP layer failure (network, status, decode).
    #[error("http: {0}")]
    Http(String),
    /// Postcard / JSON decode failure.
    #[error("decode: {0}")]
    Decode(String),
    /// ML-DSA-65 signature verification failed.
    #[error("bad signature: {0}")]
    BadSignature(String),
    /// Filesystem / cache I/O failure.
    #[error("io: {0}")]
    Io(String),
}

/// Emitted on the broadcast channel whenever a refresh produces a
/// delta against the previous in-memory index.
#[derive(Clone, Debug)]
pub struct BlockEvent {
    /// Which [`EntryKind`] changed.
    pub kind: EntryKind,
    /// Values added in this refresh.
    pub added: Vec<String>,
    /// Values removed in this refresh.
    pub removed: Vec<String>,
}

/// Multi-kind denylist consumer.
///
/// Subscribes to ALL four [`EntryKind`] feeds from a single
/// `fetch_url_base` (e.g. `https://etchit.io/v1`) and exposes a
/// unified [`Self::is_blocked`] lookup. Implements
/// [`fetchit_trust::DenylistQuery`] (in C7) for injection into the
/// chat and reader code paths.
///
/// The in-memory index is protected by a `std::sync::RwLock`: reads
/// are the hot path (every inbound chat envelope, every reader
/// `XorName` fetch) and are uncontended except during the rare
/// refresh swap, so a synchronous lock keeps the lookup side from
/// having to be async.
pub struct DenylistConsumer {
    issuer_public_key_bytes: Vec<u8>,
    fetch_url_base: String,
    indexes: Arc<RwLock<DenylistIndexes>>,
    cache_path: Option<PathBuf>,
    tx: broadcast::Sender<BlockEvent>,
    poll_interval: std::time::Duration,
}

impl DenylistConsumer {
    /// Construct a consumer that polls `fetch_url_base` against
    /// `issuer_public_key_bytes`. `fetch_url_base` is the v1 root,
    /// e.g. `https://etchit.io/v1`; the per-kind endpoints are
    /// derived by appending `/denylist?kind=<kind>`.
    #[must_use]
    pub fn new(
        issuer_public_key_bytes: Vec<u8>,
        fetch_url_base: String,
        cache_path: Option<PathBuf>,
    ) -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            issuer_public_key_bytes,
            fetch_url_base,
            indexes: Arc::new(RwLock::new(DenylistIndexes::default())),
            cache_path,
            tx,
            poll_interval: DEFAULT_POLL_INTERVAL,
        }
    }

    /// Override the background poll cadence used by
    /// [`Self::spawn_poll_loop`]. Defaults to [`DEFAULT_POLL_INTERVAL`]
    /// (6 hours).
    #[must_use]
    pub fn with_poll_interval(mut self, interval: std::time::Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Current poll-loop cadence. Exposed for ops/diagnostic
    /// surfaces that want to display the effective refresh interval.
    #[must_use]
    pub fn poll_interval(&self) -> std::time::Duration {
        self.poll_interval
    }

    /// Subscribe to [`BlockEvent`]s emitted on every refresh that
    /// produces a non-empty delta. Capacity is bounded (256); slow
    /// consumers may lag and observe `RecvError::Lagged` on the next
    /// recv, in which case they should resync from the current index
    /// snapshot.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<BlockEvent> {
        self.tx.subscribe()
    }

    /// Spawn a tokio task that periodically refreshes the consumer
    /// against `client`. The first refresh fires on the first
    /// interval tick (`tokio::time::interval` default behaviour) and
    /// subsequent refreshes fire on the configured interval.
    ///
    /// Refresh errors are logged via `tracing::warn!` and do NOT
    /// stop the loop, so the prior good index for each kind stays
    /// valid past a transient fetch failure.
    ///
    /// The returned [`tokio::task::JoinHandle`] lets the caller
    /// `abort()` the loop on shutdown.
    pub fn spawn_poll_loop<C: HttpClient + Send + Sync + 'static>(
        self: Arc<Self>,
        client: Arc<C>,
    ) -> tokio::task::JoinHandle<()> {
        let interval_dur = self.poll_interval;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval_dur);
            loop {
                ticker.tick().await;
                if let Err(e) = self.refresh(client.as_ref()).await {
                    tracing::warn!(error = %e, "denylist refresh");
                }
            }
        })
    }

    /// Refresh all four kinds from `client`. Per-kind errors are
    /// logged via `tracing::warn!` and SWALLOWED — the previous good
    /// index for that kind is preserved. Returns `Ok(())` when at
    /// least one kind refreshed successfully, or the last per-kind
    /// error when every kind failed.
    ///
    /// # Errors
    /// Returns the last per-kind error when none of the four
    /// refreshes succeeded.
    pub async fn refresh<C: HttpClient + ?Sized>(&self, client: &C) -> Result<(), TrustError> {
        let mut last_err: Option<TrustError> = None;
        let mut any_ok = false;
        for kind in ALL_KINDS {
            match self.refresh_one(client, kind).await {
                Ok(()) => any_ok = true,
                Err(e) => {
                    tracing::warn!(
                        ?kind,
                        error = %e,
                        "denylist refresh failed; preserving prior index for kind"
                    );
                    last_err = Some(e);
                }
            }
        }
        if any_ok {
            Ok(())
        } else {
            Err(last_err.unwrap_or_else(|| TrustError::Http("no kinds refreshed".into())))
        }
    }

    async fn refresh_one<C: HttpClient + ?Sized>(
        &self,
        client: &C,
        kind: EntryKind,
    ) -> Result<(), TrustError> {
        let url = format!(
            "{}/denylist?kind={}",
            self.fetch_url_base,
            kind_query_str(kind)
        );
        let bytes = client.get(&url).await?;
        let resp: DenylistResponse =
            serde_json::from_slice(&bytes).map_err(|e| TrustError::Decode(e.to_string()))?;
        if resp.kind != kind {
            return Err(TrustError::Decode(format!(
                "response kind {:?} does not match requested {:?}",
                resp.kind, kind
            )));
        }
        verify_signature(&resp, &self.issuer_public_key_bytes)
            .map_err(|e| TrustError::BadSignature(e.to_string()))?;
        let values: Vec<String> = resp
            .entries
            .iter()
            .map(|e| e.target.value.clone())
            .collect();
        let delta = {
            let mut idx = self
                .indexes
                .write()
                .map_err(|e| TrustError::Io(format!("index lock poisoned: {e}")))?;
            idx.replace(resp.kind, values)
        };

        // Persist to disk before emitting the event so on-crash
        // recovery sees the new state too. Best-effort: a write
        // failure does not roll back the in-memory index; the next
        // refresh will retry the write.
        if let Some(dir) = &self.cache_path {
            if let Err(e) = crate::cache::write_kind(dir, kind, &bytes) {
                tracing::warn!(
                    ?kind,
                    error = %e,
                    "denylist cache write failed; in-memory index still updated"
                );
            }
        }

        if !delta.added.is_empty() || !delta.removed.is_empty() {
            let event = BlockEvent {
                kind: delta.kind,
                added: delta.added,
                removed: delta.removed,
            };
            // Best-effort: drops silently when there are no
            // subscribers. The index swap already happened; push
            // notification is a courtesy, not a correctness
            // requirement.
            let _ = self.tx.send(event);
        }
        Ok(())
    }

    /// Synchronously load any cached `DenylistResponse` files from
    /// `cache_path` and hydrate the in-memory index. Each kind is
    /// re-verified against the issuer pubkey; corrupt or
    /// mismatched-signature files are logged and skipped (the next
    /// online refresh will overwrite them).
    ///
    /// Call once at boot, BEFORE the first lookup, when offline
    /// availability matters. No-op when `cache_path` is `None`.
    ///
    /// Per-kind failure isolation: a poisoned `relay_url.json` does
    /// not prevent a valid `agent_id.json` from hydrating.
    pub fn load_cache_blocking(&self) {
        let Some(dir) = &self.cache_path else {
            return;
        };
        for kind in ALL_KINDS {
            let bytes = match crate::cache::read_kind(dir, kind) {
                Ok(Some(b)) => b,
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(?kind, error = %e, "denylist cache read failed");
                    continue;
                }
            };
            let resp: DenylistResponse = match serde_json::from_slice(&bytes) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        ?kind,
                        error = %e,
                        "denylist cache decode failed; ignoring file"
                    );
                    continue;
                }
            };
            if resp.kind != kind {
                tracing::warn!(
                    ?kind,
                    found = ?resp.kind,
                    "denylist cache kind mismatch; ignoring"
                );
                continue;
            }
            if let Err(e) = verify_signature(&resp, &self.issuer_public_key_bytes) {
                tracing::warn!(
                    ?kind,
                    error = %e,
                    "denylist cache signature mismatch; ignoring"
                );
                continue;
            }
            let values: Vec<String> = resp
                .entries
                .iter()
                .map(|e| e.target.value.clone())
                .collect();
            let mut idx = match self.indexes.write() {
                Ok(g) => g,
                Err(e) => {
                    tracing::warn!(
                        ?kind,
                        error = %e,
                        "index lock poisoned during cache load"
                    );
                    continue;
                }
            };
            idx.replace(kind, values);
        }
    }

    /// `true` when `(kind, value)` is on the current snapshot.
    ///
    /// Synchronous: the index lock is held only for the duration of
    /// the lookup. Safe to call from sync or async contexts.
    #[must_use]
    pub fn is_blocked(&self, kind: EntryKind, value: &str) -> bool {
        match self.indexes.read() {
            Ok(idx) => idx.is_blocked(kind, value),
            Err(poisoned) => poisoned.into_inner().is_blocked(kind, value),
        }
    }
}

impl fetchit_trust::DenylistQuery for DenylistConsumer {
    fn is_blocked(&self, kind: EntryKind, value: &str) -> bool {
        DenylistConsumer::is_blocked(self, kind, value)
    }
}

fn kind_query_str(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::XorName => "xor_name",
        EntryKind::AgentId => "agent_id",
        EntryKind::RelayUrl => "relay_url",
        EntryKind::ActorUrl => "actor_url",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::http::HttpClient;
    use async_trait::async_trait;
    use fetchit_trust::signer::IssuerSigner;
    use fetchit_trust::types::{
        DenylistEntry, DenylistResponse, DenylistToSign, ReportKind, TargetIdentity,
    };
    use fetchit_trust::EntryKind;
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn signed_response(
        signer: &IssuerSigner,
        kind: EntryKind,
        values: &[&str],
    ) -> DenylistResponse {
        let entries: Vec<DenylistEntry> = values
            .iter()
            .map(|v| DenylistEntry {
                target: TargetIdentity::new(kind, *v),
                added_at_ms: 1_700_000_000_000,
                reason: ReportKind::Spam,
            })
            .collect();
        let to_sign = DenylistToSign {
            etag: "etag-1",
            generated_at_ms: 1_700_000_000_001,
            kind,
            entries: &entries,
        };
        let sign_bytes = postcard::to_allocvec(&to_sign).unwrap();
        let sig = signer.sign(&sign_bytes).unwrap();
        DenylistResponse {
            etag: "etag-1".into(),
            generated_at_ms: 1_700_000_000_001,
            kind,
            entries,
            issuer_signature_hex: hex::encode(sig),
            issuer_key_id: signer.key_id.clone(),
        }
    }

    /// Test HTTP stub. Pre-bake responses by URL substring; return
    /// 404-equivalent (Err) for unmatched URLs.
    struct StubHttp {
        by_kind: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl StubHttp {
        fn new() -> Self {
            Self {
                by_kind: Mutex::new(HashMap::new()),
            }
        }
        fn pre_bake(&self, kind_query: &str, body: Vec<u8>) {
            self.by_kind.lock().unwrap().insert(kind_query.into(), body);
        }
    }

    #[async_trait]
    impl HttpClient for StubHttp {
        async fn get(&self, url: &str) -> Result<Vec<u8>, TrustError> {
            let map = self.by_kind.lock().unwrap();
            for (kind_query, body) in map.iter() {
                if url.contains(kind_query) {
                    return Ok(body.clone());
                }
            }
            Err(TrustError::Http(format!("stub: no body for {url}")))
        }
    }

    fn json_bytes(resp: &DenylistResponse) -> Vec<u8> {
        serde_json::to_vec(resp).unwrap()
    }

    #[tokio::test]
    async fn refresh_indexes_signed_relay_url_entries() {
        let signer = IssuerSigner::generate("test").unwrap();
        let stub = StubHttp::new();
        let resp = signed_response(&signer, EntryKind::RelayUrl, &["wss://bad.example/v1/ws"]);
        stub.pre_bake("relay_url", json_bytes(&resp));

        let consumer = DenylistConsumer::new(
            signer.public_key_bytes(),
            "https://etchit.io/v1".into(),
            None,
        );
        consumer.refresh(&stub).await.unwrap();
        assert!(consumer.is_blocked(EntryKind::RelayUrl, "wss://bad.example/v1/ws"));
    }

    #[tokio::test]
    async fn refresh_rejects_bad_signature_keeps_old_index() {
        let good_signer = IssuerSigner::generate("good").unwrap();
        let bad_signer = IssuerSigner::generate("bad").unwrap();
        let consumer = DenylistConsumer::new(
            good_signer.public_key_bytes(),
            "https://etchit.io/v1".into(),
            None,
        );

        // First refresh: good signer, succeeds.
        let stub1 = StubHttp::new();
        let resp1 = signed_response(&good_signer, EntryKind::RelayUrl, &["wss://a"]);
        stub1.pre_bake("relay_url", json_bytes(&resp1));
        consumer.refresh(&stub1).await.ok(); // Some other kinds may 404 in stub, that's OK.
        assert!(consumer.is_blocked(EntryKind::RelayUrl, "wss://a"));

        // Second refresh: bad signer for the same kind.
        let stub2 = StubHttp::new();
        let resp2 = signed_response(&bad_signer, EntryKind::RelayUrl, &["wss://b"]);
        stub2.pre_bake("relay_url", json_bytes(&resp2));
        let _ = consumer.refresh(&stub2).await; // Per-kind failure swallowed; refresh may still report Ok if others fail soft.
        assert!(consumer.is_blocked(EntryKind::RelayUrl, "wss://a"));
        assert!(!consumer.is_blocked(EntryKind::RelayUrl, "wss://b"));
    }

    #[tokio::test]
    async fn is_blocked_works_through_dyn_trait() {
        use fetchit_trust::DenylistQuery;
        use std::sync::Arc;

        let signer = IssuerSigner::generate("test").unwrap();
        let stub = StubHttp::new();
        let resp = signed_response(&signer, EntryKind::AgentId, &["a".repeat(64).as_str()]);
        stub.pre_bake("agent_id", json_bytes(&resp));

        let consumer = Arc::new(DenylistConsumer::new(
            signer.public_key_bytes(),
            "https://etchit.io/v1".into(),
            None,
        ));
        consumer.refresh(&stub).await.unwrap();

        let dyn_q: Arc<dyn DenylistQuery> = consumer.clone() as Arc<dyn DenylistQuery>;
        assert!(dyn_q.is_blocked(EntryKind::AgentId, &"a".repeat(64)));
        assert!(!dyn_q.is_blocked(EntryKind::AgentId, &"b".repeat(64)));
    }

    #[tokio::test]
    async fn subscribe_receives_block_events_on_refresh() {
        use std::time::Duration;
        use tokio::time::timeout;

        let signer = IssuerSigner::generate("test").unwrap();
        let stub = StubHttp::new();
        let resp = signed_response(&signer, EntryKind::RelayUrl, &["wss://bad.example/v1/ws"]);
        stub.pre_bake("relay_url", json_bytes(&resp));

        let consumer = DenylistConsumer::new(
            signer.public_key_bytes(),
            "https://etchit.io/v1".into(),
            None,
        );
        let mut rx = consumer.subscribe();
        consumer.refresh(&stub).await.unwrap();

        let evt = timeout(Duration::from_millis(200), rx.recv())
            .await
            .expect("event arrives within 200ms")
            .expect("channel not closed");
        assert_eq!(evt.kind, EntryKind::RelayUrl);
        assert_eq!(evt.added, vec!["wss://bad.example/v1/ws".to_string()]);
        assert!(evt.removed.is_empty());
    }

    #[tokio::test]
    async fn subscribe_no_event_on_idempotent_refresh() {
        use std::time::Duration;
        use tokio::time::timeout;

        let signer = IssuerSigner::generate("test").unwrap();
        let stub = StubHttp::new();
        let resp = signed_response(&signer, EntryKind::AgentId, &["a".repeat(64).as_str()]);
        stub.pre_bake("agent_id", json_bytes(&resp));

        let consumer = DenylistConsumer::new(
            signer.public_key_bytes(),
            "https://etchit.io/v1".into(),
            None,
        );
        consumer.refresh(&stub).await.unwrap();
        let mut rx = consumer.subscribe();
        consumer.refresh(&stub).await.unwrap(); // identical snapshot

        // No delta -> no BlockEvent for AgentId. (Other kinds may emit because
        // their first refresh transitions empty -> empty too, which also no-ops.
        // The assertion is that we don't see an AgentId event referencing
        // the "a"*64 value as added a second time.)
        let result = timeout(Duration::from_millis(100), rx.recv()).await;
        if let Ok(Ok(evt)) = result {
            assert!(
                !(evt.kind == EntryKind::AgentId && evt.added.contains(&"a".repeat(64))),
                "should not re-emit added for an idempotent refresh"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn poll_loop_refreshes_on_interval() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::time::Duration;

        struct CountingStub {
            inner: StubHttp,
            count: AtomicUsize,
        }

        impl CountingStub {
            fn new() -> Self {
                Self {
                    inner: StubHttp::new(),
                    count: AtomicUsize::new(0),
                }
            }
            fn count(&self) -> usize {
                self.count.load(Ordering::SeqCst)
            }
        }

        #[async_trait]
        impl HttpClient for CountingStub {
            async fn get(&self, url: &str) -> Result<Vec<u8>, TrustError> {
                self.count.fetch_add(1, Ordering::SeqCst);
                self.inner.get(url).await
            }
        }

        let signer = IssuerSigner::generate("test").unwrap();
        let stub = Arc::new(CountingStub::new());
        let resp = signed_response(&signer, EntryKind::RelayUrl, &["wss://r.example/v1/ws"]);
        stub.inner.pre_bake("relay_url", json_bytes(&resp));

        let consumer = Arc::new(
            DenylistConsumer::new(
                signer.public_key_bytes(),
                "https://etchit.io/v1".into(),
                None,
            )
            .with_poll_interval(Duration::from_secs(60)),
        );
        let _handle = Arc::clone(&consumer).spawn_poll_loop(Arc::clone(&stub));

        // First tick: 60s. tokio::time::interval fires immediately on the
        // first .tick().await — that's why the initial-tick semantics are
        // tested separately. Sleep 1ms to let the first refresh fire.
        tokio::time::sleep(Duration::from_millis(1)).await;
        let after_first = stub.count();
        assert!(
            after_first >= 4,
            "initial tick should refresh all 4 kinds (got {after_first})"
        );

        // Advance virtual time past one full interval. Refresh fires again.
        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::time::sleep(Duration::from_millis(1)).await;
        let after_second = stub.count();
        assert!(
            after_second >= 8,
            "second tick should add 4 more refreshes (got {after_second})"
        );
    }

    #[tokio::test]
    async fn with_poll_interval_overrides_default() {
        // Just a unit-test of the builder, no real loop spawn.
        let signer = IssuerSigner::generate("test").unwrap();
        let consumer = DenylistConsumer::new(
            signer.public_key_bytes(),
            "https://etchit.io/v1".into(),
            None,
        )
        .with_poll_interval(std::time::Duration::from_secs(120));
        assert_eq!(
            consumer.poll_interval(),
            std::time::Duration::from_secs(120)
        );
    }

    #[tokio::test]
    async fn refresh_iterates_all_four_kinds() {
        let signer = IssuerSigner::generate("test").unwrap();
        let stub = StubHttp::new();
        for kind in [
            EntryKind::XorName,
            EntryKind::AgentId,
            EntryKind::RelayUrl,
            EntryKind::ActorUrl,
        ] {
            let val = match kind {
                EntryKind::XorName | EntryKind::AgentId => "a".repeat(64),
                EntryKind::RelayUrl => "wss://r.example/v1/ws".to_string(),
                EntryKind::ActorUrl => "https://m.example/users/a".to_string(),
            };
            let resp = signed_response(&signer, kind, &[&val]);
            let url_segment = match kind {
                EntryKind::XorName => "xor_name",
                EntryKind::AgentId => "agent_id",
                EntryKind::RelayUrl => "relay_url",
                EntryKind::ActorUrl => "actor_url",
            };
            stub.pre_bake(url_segment, json_bytes(&resp));
        }
        let consumer = DenylistConsumer::new(
            signer.public_key_bytes(),
            "https://etchit.io/v1".into(),
            None,
        );
        consumer.refresh(&stub).await.unwrap();
        assert!(consumer.is_blocked(EntryKind::XorName, &"a".repeat(64)));
        assert!(consumer.is_blocked(EntryKind::AgentId, &"a".repeat(64)));
        assert!(consumer.is_blocked(EntryKind::RelayUrl, "wss://r.example/v1/ws"));
        assert!(consumer.is_blocked(EntryKind::ActorUrl, "https://m.example/users/a"));
    }
}
