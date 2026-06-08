//! Fediverse `/inbox` endpoint — receive side of the M4 bridge.
//!
//! Gated behind the `fediverse-inbox` Cargo feature so the default
//! relay-server (LIT Chat pass-through) ships without any fediverse
//! code or its dep tree. Community-relay operators that opt in to the
//! fediverse-inbox role build with `--features fediverse-inbox` per
//! `docs/superpowers/plans/2026-06-07-m4-fediverse-impl-plan.md`
//! Stage 7.
//!
//! ## Stage 3.1b — scaffold + 5 pre-flight gates
//!
//! Per the M4 plan's Stage 3 hardening checklist:
//!
//! 1. **Body size cap** — reject `Content-Length > 1 MB` with `413
//!    Payload Too Large`. Mastodon's typical activity body is ~64 KB;
//!    1 MB is generous but bounded.
//! 2. **Rate-limit per source-instance** — token bucket keyed by
//!    remote instance hostname (parsed out of the signing actor's
//!    keyId URL). Mirrors [`crate::ratelimit::RateLimiter`] (R-002)
//!    in shape.
//! 3. **HTTP Signature verification** — using the RFC 9421 +
//!    draft-cavage verifier helpers in
//!    [`fetchit_fedi::signature::verify_signature_rfc9421`] /
//!    [`fetchit_fedi::signature_cavage::verify_signature_cavage`].
//!    `Date` skew and `Signature-Input;created` freshness checks live
//!    here too.
//! 4. **Replay window** — sliding 5-minute cache of `(Content-Digest,
//!    Date)` pairs, ~100k LRU cap. Bounded memory, drops duplicates.
//! 5. **Denylist** — `InboxDenylistCheck::is_blocked_actor` is the
//!    Stage 4 `EntryKind::ActorUrl` consultation point.
//!
//! ## Metrics
//!
//! Each gate produces a [`DropReason`] variant on rejection. Stage 3.2
//! wires `fedi_inbox_dropped_*_total{...}` Prometheus counters into
//! `crate::metrics::Metrics` against these reasons — 3.1b stops
//! before metric increments so the wire shape stays reviewable on
//! its own.

pub mod metrics;
pub mod operator;
pub mod rate_limit;
pub mod replay;
pub mod router;
pub mod sig_verify;
pub mod sink;

pub use metrics::{InboxMetrics, ScalarDropSnapshot};
pub use rate_limit::InboxRateLimit;
pub use replay::ReplayWindow;
pub use router::{inbox_router, InboxState, PendingDelivery};
pub use sig_verify::{InboxSignatureContext, SignatureScheme};
pub use sink::SessionBroadcastSink;

use thiserror::Error;

/// Reason a request was dropped on the inbox pre-flight, sized to
/// map 1-to-1 with the Stage 3.2 Prom counter cardinality. New
/// variants are NEW Prom label slots — bias toward folding into
/// existing variants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DropReason {
    /// `Content-Length` (or actual body) exceeded
    /// [`InboxState::max_body_bytes`].
    BodyTooLarge,
    /// Per-source-instance rate limit exhausted. Carries the parsed
    /// instance hostname so the counter can label by source.
    RateLimited(String),
    /// Date header outside the configured ±skew window, OR
    /// `Signature-Input;created` outside the same window.
    StaleRequest,
    /// `(Content-Digest, Date)` already seen in the replay window.
    Replay,
    /// HTTP Signature verification failed — invalid format,
    /// digest mismatch, signature decode failure, or RSA verify
    /// failure. Carries the
    /// [`fetchit_fedi::signature::SignatureVerifyError::reason_label`]
    /// for the counter sub-slot.
    SigFail(&'static str),
    /// Cavage `algorithm=` parameter is not `"rsa-sha256"`. Per
    /// Alice's I2 from the 3.1a cross-review — fail-closed semantics
    /// are already correct via the RSA verify, but an explicit
    /// early-reject + dedicated counter slot catches misconfigured
    /// senders before the expensive math op.
    UnsupportedAlgorithm,
    /// `is_blocked_actor` returned true. Carries the actor URL the
    /// denylist matched so the counter can label by kind (Stage 4
    /// `EntryKind::ActorUrl` consumer + secondary Mastodon-blocklist).
    Denylisted(String),
    /// `WebFinger` lookup failed — actor not resolvable to a pubkey.
    /// Mapped onto `sig_fail{reason="webfinger"}` to keep the
    /// counter family compact.
    WebFingerLookupFailed,
    /// The `keyId` parameter (RFC 9421) or `keyId="..."` (cavage)
    /// was missing, malformed, or could not be parsed into an actor
    /// URL.
    MissingKeyId,
    /// A required header (`Date`, `Content-Digest`, `Signature-Input`,
    /// `Signature`, `Host`, `Digest`) was missing.
    MissingHeader(&'static str),
    /// The delivery sink (Stage 3.3's `EnvelopeKind::PublicPost`
    /// out-stream) refused to enqueue — backpressure, queue full, or
    /// receiver disconnected.
    SinkRejected,
}

impl DropReason {
    /// Short stable label for Prometheus drop-reason counters.
    /// Keep the set small — every new label is a new
    /// high-cardinality slot.
    #[must_use]
    pub fn counter_label(&self) -> &'static str {
        match self {
            Self::BodyTooLarge => "body_too_large",
            Self::RateLimited(_) => "rate_limited",
            Self::StaleRequest => "stale_request",
            Self::Replay => "replay",
            Self::SigFail(_) => "sig_fail",
            Self::UnsupportedAlgorithm => "unsupported_algorithm",
            Self::Denylisted(_) => "denylisted",
            Self::WebFingerLookupFailed => "webfinger_lookup_failed",
            Self::MissingKeyId => "missing_keyid",
            Self::MissingHeader(_) => "missing_header",
            Self::SinkRejected => "sink_rejected",
        }
    }
}

/// Wrapper error type carrying a [`DropReason`] alongside the axum
/// status code the gate intends to surface.
#[derive(Debug, Error)]
#[error("inbox request dropped: {reason:?}")]
pub struct InboxError {
    /// Why the request was dropped.
    pub reason: DropReason,
    /// HTTP status the handler will return.
    pub status: u16,
}

impl InboxError {
    /// Construct a drop with `status = 400 Bad Request`.
    #[must_use]
    pub fn bad_request(reason: DropReason) -> Self {
        Self {
            reason,
            status: 400,
        }
    }

    /// Construct a drop with `status = 413 Payload Too Large`.
    #[must_use]
    pub fn payload_too_large() -> Self {
        Self {
            reason: DropReason::BodyTooLarge,
            status: 413,
        }
    }

    /// Construct a drop with `status = 401 Unauthorized` (signature
    /// failure).
    #[must_use]
    pub fn unauthorized(reason: DropReason) -> Self {
        Self {
            reason,
            status: 401,
        }
    }

    /// Construct a drop with `status = 403 Forbidden` (denylist or
    /// algorithm policy).
    #[must_use]
    pub fn forbidden(reason: DropReason) -> Self {
        Self {
            reason,
            status: 403,
        }
    }

    /// Construct a drop with `status = 429 Too Many Requests` (rate
    /// limit).
    #[must_use]
    pub fn too_many_requests(reason: DropReason) -> Self {
        Self {
            reason,
            status: 429,
        }
    }

    /// Construct a drop with `status = 503 Service Unavailable` (sink
    /// rejected — relay-WS receiver is gone).
    #[must_use]
    pub fn service_unavailable(reason: DropReason) -> Self {
        Self {
            reason,
            status: 503,
        }
    }
}

/// Local trait the inbox calls to determine whether a sending actor
/// (parsed from the HTTP Signature `keyId`) is denylisted.
///
/// Stage 4 lands the production impl that consults
/// `fetchit_trust::EntryKind::ActorUrl` plus the
/// `MastodonBlocklistConsumer`. The trait stays in this crate so
/// the relay-server doesn't pull `fetchit-chat` into its dep tree.
#[async_trait::async_trait]
pub trait InboxDenylistCheck: Send + Sync {
    /// `true` when `actor_url` is blocked (matched by either the
    /// `etchit-io`-signed denylist or a configured secondary
    /// blocklist).
    async fn is_blocked_actor(&self, actor_url: &str) -> bool;
}

/// Errors a `WebFingerLookup` impl can surface.
#[derive(Debug, Error)]
pub enum WebFingerError {
    /// The actor URL did not resolve to any record.
    #[error("WebFinger record not found for {0}")]
    NotFound(String),
    /// Network or HTTP transport error.
    #[error("WebFinger network error: {0}")]
    Network(String),
    /// The actor JSON-LD was malformed — missing `publicKey` /
    /// `publicKeyPem` / etc.
    #[error("malformed WebFinger response: {0}")]
    Malformed(String),
}

/// Local trait the inbox calls to resolve an actor's RSA pubkey
/// PEM from its `keyId` URL.
///
/// Production impl lives in `fetchit-fedi` (Stage 6.1 `WebFinger`
/// client + the TTL cache that Alice's M4 plan Stage 3 gate 5
/// describes). The trait stays in this crate so the relay-server
/// doesn't depend on a network-fetching client at compile time —
/// tests inject a stub.
#[async_trait::async_trait]
pub trait WebFingerLookup: Send + Sync {
    /// Resolve the actor's RSA public-key PEM by `keyId` URL.
    ///
    /// # Errors
    /// Implementation-defined.
    async fn resolve_pubkey_pem(&self, key_id: &str) -> Result<String, WebFingerError>;

    /// Invalidate any cached entry for `key_id`, forcing a fresh
    /// fetch on the next call. The inbox handler calls this after a
    /// signature verification fails on the assumption that the actor
    /// rotated their key.
    async fn invalidate(&self, key_id: &str);
}

/// Sink for activities that made it through every pre-flight gate.
///
/// Stage 3.3 lands the production impl that turns the validated
/// activity into an `EnvelopeKind::PublicPost` on the relay-WS
/// out-stream so the chat-layer drains it like any other envelope.
#[async_trait::async_trait]
pub trait PendingDeliverySink: Send + Sync {
    /// Enqueue a `delivery` for downstream chat-layer dispatch.
    ///
    /// # Errors
    /// `Err(())` indicates the sink rejected — backpressure, queue
    /// full, receiver disconnected. Maps onto
    /// [`DropReason::SinkRejected`].
    async fn enqueue(&self, delivery: PendingDelivery) -> Result<(), ()>;
}
