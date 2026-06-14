//! Client-side denylist consumer.
//!
//! Stage 2 Tasks 2.1-2.2 of M3 federation core
//! (`docs/superpowers/plans/2026-06-06-m3-federation-core-plan.md`).
//! Reads a published [`DenylistResponse`], verifies the issuer's
//! ML-DSA-65 signature over the canonical
//! [`crate::types::DenylistToSign`] payload, caches the targeted
//! `TargetIdentity` set, and answers fast lookups.
//!
//! [`VerifiedDenylist`] is the pure verify-and-lookup type. The
//! [`DenylistConsumer`] above wraps it in an HTTPS poller with an
//! hourly refresh loop suitable for a chat-peer or relay deployment.

use crate::error::TrustError;
use crate::types::{DenylistEntry, DenylistResponse, DenylistToSign, EntryKind, TargetIdentity};
use saorsa_pqc::api::sig::{MlDsa, MlDsaPublicKey, MlDsaSignature, MlDsaVariant};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

/// Canonical-bytes shape the issuer signs and the consumer verifies.
///
/// # Errors
/// Returns [`TrustError::IssuerKey`] when the postcard encoding fails.
pub fn signing_bytes(response: &DenylistResponse) -> Result<Vec<u8>, TrustError> {
    let payload = DenylistToSign {
        etag: response.etag.as_str(),
        generated_at_ms: response.generated_at_ms,
        kind: response.kind,
        entries: &response.entries,
    };
    postcard::to_allocvec(&payload).map_err(|e| TrustError::IssuerKey(format!("encode: {e}")))
}

/// Verify the issuer's signature over the canonical payload.
///
/// # Errors
/// Returns [`TrustError::IssuerKey`] when the public key parse, the
/// signature parse, the encode, or the verify itself fails. Also
/// returns it when the signature does not match — same variant
/// because the caller's recourse is the same in every case: discard
/// the response.
pub fn verify_signature(
    response: &DenylistResponse,
    issuer_public_key_bytes: &[u8],
) -> Result<(), TrustError> {
    let pk = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, issuer_public_key_bytes)
        .map_err(|e| TrustError::IssuerKey(format!("pk: {e}")))?;
    let sig_bytes = hex::decode(&response.issuer_signature_hex)
        .map_err(|e| TrustError::IssuerKey(format!("sig hex: {e}")))?;
    let signature = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &sig_bytes)
        .map_err(|e| TrustError::IssuerKey(format!("sig: {e}")))?;
    let message = signing_bytes(response)?;
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    if dsa
        .verify(&pk, &message, &signature)
        .map_err(|e| TrustError::IssuerKey(format!("verify: {e}")))?
    {
        Ok(())
    } else {
        Err(TrustError::IssuerKey("signature mismatch".into()))
    }
}

/// A verified denylist snapshot ready for fast `is_blocked` lookups.
pub struct VerifiedDenylist {
    response: DenylistResponse,
    blocked: HashSet<TargetIdentity>,
}

impl VerifiedDenylist {
    /// Construct from a [`DenylistResponse`] after verifying the
    /// issuer's signature.
    ///
    /// # Errors
    /// Returns the same variants as [`verify_signature`].
    pub fn from_response(
        response: DenylistResponse,
        issuer_public_key_bytes: &[u8],
    ) -> Result<Self, TrustError> {
        verify_signature(&response, issuer_public_key_bytes)?;
        let blocked = response.entries.iter().map(|e| e.target.clone()).collect();
        Ok(Self { response, blocked })
    }

    /// Construct without signature verification.
    ///
    /// Reserved for tests and for chain-of-custody flows where the
    /// caller has already verified the response upstream.
    #[must_use]
    pub fn new_unchecked(response: DenylistResponse) -> Self {
        let blocked = response.entries.iter().map(|e| e.target.clone()).collect();
        Self { response, blocked }
    }

    /// True when `target` appears in the denylist.
    #[must_use]
    pub fn is_blocked(&self, target: &TargetIdentity) -> bool {
        self.blocked.contains(target)
    }

    /// Convenience: check a 64-hex agent id.
    #[must_use]
    pub fn is_blocked_agent_hex(&self, agent_id_hex: &str) -> bool {
        self.is_blocked(&TargetIdentity::new(EntryKind::AgentId, agent_id_hex))
    }

    /// Convenience: check a 64-hex Autonomi `XorName`.
    #[must_use]
    pub fn is_blocked_xor_name_hex(&self, xor_name_hex: &str) -> bool {
        self.is_blocked(&TargetIdentity::new(EntryKind::XorName, xor_name_hex))
    }

    /// Borrow the underlying response — useful for ops/diagnostic
    /// surfaces that want `etag` / `generated_at_ms` / `issuer_key_id`.
    #[must_use]
    pub fn response(&self) -> &DenylistResponse {
        &self.response
    }

    /// Borrow the cached entry set.
    #[must_use]
    pub fn entries(&self) -> &[DenylistEntry] {
        &self.response.entries
    }
}

/// Default refresh cadence: re-fetch the published denylist hourly.
///
/// Picked to match the published trust service's typical re-sign
/// cadence; tuned via [`DenylistConsumer::with_refresh_interval`].
pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(3600);

/// HTTPS poller that fetches a [`DenylistResponse`] on a refresh
/// cadence, verifies it, and exposes the cached snapshot for fast
/// lookups across the rest of the process.
///
/// The cache is wrapped in `Arc<RwLock<…>>`: many readers (the chat
/// layer's outbound/inbound gates) hit it concurrently; the
/// refresh loop is the only writer.
pub struct DenylistConsumer {
    /// Issuer's ML-DSA-65 public key bytes used for verify.
    issuer_public_key_bytes: Vec<u8>,
    /// Trust service endpoint, e.g. `https://etchit.io/v1/denylist/agent`.
    url: String,
    /// reqwest client. Cloned for the refresh loop; new clones reuse
    /// the underlying connection pool.
    http: reqwest::Client,
    /// Latest verified snapshot. `None` until the first successful
    /// refresh; lookups return `false` (not blocked) in that window
    /// to fail open — the chat layer would rather deliver an
    /// occasionally-from-blocked-sender message than wedge the whole
    /// receive path during a startup transient.
    cache: Arc<RwLock<Option<VerifiedDenylist>>>,
    /// Refresh cadence used by [`Self::spawn_refresh_loop`].
    refresh_interval: Duration,
}

impl DenylistConsumer {
    /// Construct a consumer that polls `url` against `issuer_public_key_bytes`.
    ///
    /// The cache starts empty — call [`Self::refresh`] before any
    /// blocking lookup matters, or kick [`Self::spawn_refresh_loop`]
    /// for an unattended hourly refresh.
    #[must_use]
    pub fn new(url: impl Into<String>, issuer_public_key_bytes: Vec<u8>) -> Self {
        Self {
            issuer_public_key_bytes,
            url: url.into(),
            http: reqwest::Client::new(),
            cache: Arc::new(RwLock::new(None)),
            refresh_interval: DEFAULT_REFRESH_INTERVAL,
        }
    }

    /// Override the default hourly refresh cadence (for tests + ops
    /// that want a tighter or wider sweep).
    #[must_use]
    pub fn with_refresh_interval(mut self, interval: Duration) -> Self {
        self.refresh_interval = interval;
        self
    }

    /// Override the default `reqwest::Client` (useful for tests that
    /// want a connection pool tuned for the local mockito server, or
    /// for ops that want their own proxy / timeout config).
    #[must_use]
    pub fn with_http_client(mut self, http: reqwest::Client) -> Self {
        self.http = http;
        self
    }

    /// Perform one refresh: HTTP GET the configured URL, parse the
    /// JSON body as [`DenylistResponse`], verify the issuer signature,
    /// and atomically swap the cache.
    ///
    /// # Errors
    /// Returns [`TrustError::Io`] on transport / status failures,
    /// and `TrustError::Issuer`-class errors when the payload doesn't
    /// verify under the configured issuer key.
    pub async fn refresh(&self) -> Result<(), TrustError> {
        let response = self
            .http
            .get(&self.url)
            .send()
            .await
            .map_err(|e| TrustError::Io(std::io::Error::other(format!("denylist GET: {e}"))))?;
        if !response.status().is_success() {
            return Err(TrustError::Io(std::io::Error::other(format!(
                "denylist GET non-success status: {}",
                response.status()
            ))));
        }
        let body: DenylistResponse = response
            .json()
            .await
            .map_err(|e| TrustError::Io(std::io::Error::other(format!("denylist body: {e}"))))?;
        let verified = VerifiedDenylist::from_response(body, &self.issuer_public_key_bytes)?;
        *self.cache.write().await = Some(verified);
        Ok(())
    }

    /// Spawn a background task that refreshes the cache on the
    /// configured cadence. The first refresh fires immediately;
    /// subsequent refreshes fire on the interval. Returns the
    /// [`JoinHandle`] so the caller can cancel on shutdown.
    ///
    /// Refresh errors are logged via `tracing::warn!` and do NOT
    /// stop the loop — the prior cache stays valid past a transient
    /// fetch failure.
    #[must_use]
    pub fn spawn_refresh_loop(self: &Arc<Self>) -> JoinHandle<()> {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(me.refresh_interval);
            loop {
                tick.tick().await;
                if let Err(e) = me.refresh().await {
                    tracing::warn!(error = %e, "denylist refresh failed; keeping prior cache");
                }
            }
        })
    }

    /// Look up an agent id directly. Returns `false` (fail-open)
    /// when no cache has been populated yet, e.g. during the first
    /// refresh after process start.
    #[must_use]
    pub async fn is_blocked_agent_hex(&self, agent_id_hex: &str) -> bool {
        let guard = self.cache.read().await;
        guard
            .as_ref()
            .is_some_and(|v| v.is_blocked_agent_hex(agent_id_hex))
    }

    /// Look up an Autonomi `XorName` directly. Same fail-open
    /// semantics as [`Self::is_blocked_agent_hex`].
    #[must_use]
    pub async fn is_blocked_xor_name_hex(&self, xor_name_hex: &str) -> bool {
        let guard = self.cache.read().await;
        guard
            .as_ref()
            .is_some_and(|v| v.is_blocked_xor_name_hex(xor_name_hex))
    }

    /// Borrow a clone of the cache handle for callers that want to
    /// do their own [`VerifiedDenylist`] reads (e.g. iterate entries
    /// for an ops dashboard).
    #[must_use]
    pub fn cache(&self) -> Arc<RwLock<Option<VerifiedDenylist>>> {
        Arc::clone(&self.cache)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::signer::IssuerSigner;
    use crate::types::ReportKind;

    fn sample_response(signer: &IssuerSigner, kind: EntryKind) -> DenylistResponse {
        let entries = vec![DenylistEntry {
            target: TargetIdentity::new(kind, "a".repeat(64)),
            added_at_ms: 1_700_000_000_000,
            reason: ReportKind::Spam,
        }];
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

    #[test]
    fn verified_denylist_round_trips_via_issuer_signature() {
        let signer = IssuerSigner::generate("test").unwrap();
        let response = sample_response(&signer, EntryKind::AgentId);
        let verified = VerifiedDenylist::from_response(response, &signer.public_key_bytes())
            .expect("signature should verify");
        assert!(verified.is_blocked_agent_hex(&"a".repeat(64)));
        assert!(!verified.is_blocked_agent_hex(&"b".repeat(64)));
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let signer = IssuerSigner::generate("test").unwrap();
        let mut response = sample_response(&signer, EntryKind::AgentId);
        // Tamper after signing: add an extra entry the issuer didn't include.
        response.entries.push(DenylistEntry {
            target: TargetIdentity::new(EntryKind::AgentId, "f".repeat(64)),
            added_at_ms: 1_700_000_000_002,
            reason: ReportKind::Other,
        });
        let res = VerifiedDenylist::from_response(response, &signer.public_key_bytes());
        assert!(res.is_err(), "tampered entries must fail verification");
    }

    #[test]
    fn verify_rejects_wrong_issuer_key() {
        let signer = IssuerSigner::generate("issuer-a").unwrap();
        let other = IssuerSigner::generate("issuer-b").unwrap();
        let response = sample_response(&signer, EntryKind::AgentId);
        let res = VerifiedDenylist::from_response(response, &other.public_key_bytes());
        assert!(res.is_err(), "wrong issuer key must fail verification");
    }

    #[tokio::test]
    async fn consumer_is_blocked_returns_false_with_empty_cache() {
        // Fail-open: before the first refresh succeeds, lookups
        // resolve "not blocked" rather than wedging the receive
        // path on a startup transient.
        let signer = IssuerSigner::generate("test").unwrap();
        let consumer = DenylistConsumer::new(
            "https://invalid.local/denylist/agent",
            signer.public_key_bytes(),
        );
        assert!(!consumer.is_blocked_agent_hex(&"a".repeat(64)).await);
        assert!(!consumer.is_blocked_xor_name_hex(&"b".repeat(64)).await);
    }

    #[tokio::test]
    async fn consumer_refresh_failure_does_not_poison_cache() {
        // Pre-seed the cache with a verified response, then call
        // refresh against an unreachable URL. The cache MUST survive
        // the failed refresh — the warning logs but the prior
        // snapshot keeps answering lookups.
        let signer = IssuerSigner::generate("test").unwrap();
        let response = sample_response(&signer, EntryKind::AgentId);
        let consumer = DenylistConsumer::new(
            "http://127.0.0.1:1/denylist/agent",
            signer.public_key_bytes(),
        );
        *consumer.cache.write().await = Some(VerifiedDenylist::new_unchecked(response));
        let res = consumer.refresh().await;
        assert!(res.is_err(), "refresh against port 1 must error");
        assert!(
            consumer.is_blocked_agent_hex(&"a".repeat(64)).await,
            "prior cache must survive a failed refresh"
        );
    }
}
