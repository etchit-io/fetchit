//! Axum router + `POST /inbox` handler for the fediverse inbox.
//!
//! Stage 3.1b orchestration layer. The handler runs the 5
//! pre-flight gates in the order documented in [`crate::inbox`]
//! then enqueues the validated activity for downstream chat-layer
//! delivery via [`PendingDeliverySink`].

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;

use super::sig_verify::{
    check_date_skew, extract_inbox_signature_context, verify_inbox_request, SignatureScheme,
};
use super::{
    DropReason, InboxDenylistCheck, InboxError, InboxRateLimit, ReplayWindow, WebFingerError,
    WebFingerLookup,
};

/// Default `Content-Length` ceiling for inbound activities — 1 MB.
/// Mastodon's typical activity body is ~64 KB; 1 MB is generous but
/// bounded.
pub const DEFAULT_MAX_BODY_BYTES: usize = 1_024 * 1_024;

/// Default ±skew window for `Date` header / `Signature-Input;created`
/// freshness checks — 5 minutes. Mirrors the replay-window length so
/// the two gates compose without leaving accept-but-evict gaps.
pub const DEFAULT_MAX_DATE_SKEW: Duration = Duration::from_secs(5 * 60);

/// Stage 3.1b inbox state shared across requests on the axum router.
///
/// All fields are `Arc<...>` so the router can be cheaply cloned for
/// every request without per-call allocation. Construct via
/// [`Self::builder`].
#[derive(Clone)]
pub struct InboxState {
    /// Per-source-instance token-bucket limiter.
    pub rate_limit: Arc<InboxRateLimit>,
    /// Sliding-window replay cache.
    pub replay: Arc<ReplayWindow>,
    /// Denylist consultation point (Stage 4 wires the real
    /// `EntryKind::ActorUrl` consumer here).
    pub denylist: Arc<dyn InboxDenylistCheck>,
    /// `WebFinger` pubkey resolver (Stage 6.1 wires the cached
    /// HTTPS client here).
    pub webfinger: Arc<dyn WebFingerLookup>,
    /// Sink for activities that pass every gate (Stage 3.3 wires the
    /// `EnvelopeKind::PublicPost` out-stream here).
    pub sink: Arc<dyn PendingDeliverySink>,
    /// Hard ceiling on inbound body size (gate 4).
    pub max_body_bytes: usize,
    /// Maximum ±skew for `Date` + `Signature-Input;created`.
    pub max_date_skew: Duration,
}

impl InboxState {
    /// Builder helper — fewer parameters than the all-positional
    /// `new` would have. Set `max_body_bytes` / `max_date_skew` via
    /// the `.with_*` setters; defaults match
    /// [`DEFAULT_MAX_BODY_BYTES`] / [`DEFAULT_MAX_DATE_SKEW`].
    #[must_use]
    pub fn builder(
        denylist: Arc<dyn InboxDenylistCheck>,
        webfinger: Arc<dyn WebFingerLookup>,
        sink: Arc<dyn PendingDeliverySink>,
    ) -> InboxStateBuilder {
        InboxStateBuilder {
            rate_limit: Arc::new(InboxRateLimit::new(60)),
            replay: Arc::new(ReplayWindow::default()),
            denylist,
            webfinger,
            sink,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_date_skew: DEFAULT_MAX_DATE_SKEW,
        }
    }
}

/// Builder for [`InboxState`].
pub struct InboxStateBuilder {
    rate_limit: Arc<InboxRateLimit>,
    replay: Arc<ReplayWindow>,
    denylist: Arc<dyn InboxDenylistCheck>,
    webfinger: Arc<dyn WebFingerLookup>,
    sink: Arc<dyn PendingDeliverySink>,
    max_body_bytes: usize,
    max_date_skew: Duration,
}

impl InboxStateBuilder {
    /// Swap in a pre-configured rate limiter (e.g. with a non-default
    /// `rate_per_min`).
    #[must_use]
    pub fn with_rate_limit(mut self, rl: Arc<InboxRateLimit>) -> Self {
        self.rate_limit = rl;
        self
    }

    /// Swap in a pre-configured replay window (e.g. test-shaped
    /// shorter window or smaller cap).
    #[must_use]
    pub fn with_replay(mut self, w: Arc<ReplayWindow>) -> Self {
        self.replay = w;
        self
    }

    /// Override `max_body_bytes`.
    #[must_use]
    pub fn with_max_body_bytes(mut self, max: usize) -> Self {
        self.max_body_bytes = max;
        self
    }

    /// Override `max_date_skew`.
    #[must_use]
    pub fn with_max_date_skew(mut self, skew: Duration) -> Self {
        self.max_date_skew = skew;
        self
    }

    /// Finalize the [`InboxState`].
    #[must_use]
    pub fn build(self) -> InboxState {
        InboxState {
            rate_limit: self.rate_limit,
            replay: self.replay,
            denylist: self.denylist,
            webfinger: self.webfinger,
            sink: self.sink,
            max_body_bytes: self.max_body_bytes,
            max_date_skew: self.max_date_skew,
        }
    }
}

/// Activity that made it through every pre-flight gate — enqueued
/// for the chat-layer to drain (Stage 3.3 turns this into an
/// `EnvelopeKind::PublicPost` on the relay-WS out-stream).
#[derive(Clone, Debug)]
pub struct PendingDelivery {
    /// Signing actor URL (from the verified `keyId`).
    pub actor_url: String,
    /// Wire format the sender used.
    pub scheme: SignatureScheme,
    /// Raw activity body — opaque JSON-LD bytes the chat layer
    /// parses downstream.
    pub body: Vec<u8>,
    /// When the inbox accepted the request.
    pub received_at: SystemTime,
}

/// Sink for activities that pass every gate. Re-exported from
/// [`super`] for ergonomics.
pub use super::PendingDeliverySink;

/// Build the axum router exposing the inbox endpoint.
///
/// Mounts at `/inbox` so callers can either use this router
/// standalone (`axum::serve(listener, inbox_router(state))`) or
/// `.merge()` it onto an existing relay-server router (Stage 3.3
/// wires it onto `Server::router()`).
pub fn inbox_router(state: InboxState) -> Router {
    Router::new()
        .route("/inbox", post(handle_inbox))
        .with_state(state)
}

/// Axum handler — runs every gate in order, returns the status code
/// each gate's `InboxError` carries.
async fn handle_inbox(
    State(state): State<InboxState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match handle_inbox_inner(state, headers, body).await {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(err) => (
            StatusCode::from_u16(err.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            format!("{:?}", err.reason),
        )
            .into_response(),
    }
}

/// Inner handler logic — runs the 5 pre-flight gates in order.
/// Separated from [`handle_inbox`] so the orchestration is
/// `?`-ergonomic and the unit tests can drive it without the
/// axum layer.
async fn handle_inbox_inner(
    state: InboxState,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(), InboxError> {
    // Gate 4: body size.
    if body.len() > state.max_body_bytes {
        return Err(InboxError::payload_too_large());
    }

    // Gate 2 prereqs: pull every required header, reconstruct
    // target_uri / request_target.
    let ctx =
        extract_inbox_signature_context(&headers, "/inbox").map_err(|reason| match reason {
            DropReason::MissingHeader(_) | DropReason::MissingKeyId => {
                InboxError::bad_request(reason)
            }
            _ => InboxError::unauthorized(reason),
        })?;

    // Gate 2a: Date skew (RFC 9421 freshness window).
    check_date_skew(&ctx.date, SystemTime::now(), state.max_date_skew)
        .map_err(InboxError::bad_request)?;

    // Gate 1: rate-limit by source-instance hostname (parsed from
    // keyId).
    let instance = parse_instance(&ctx.key_id)
        .ok_or_else(|| InboxError::bad_request(DropReason::MissingKeyId))?;
    if !state.rate_limit.allow(&instance) {
        return Err(InboxError::too_many_requests(DropReason::RateLimited(
            instance,
        )));
    }

    // Gate 5: denylist. Done before signature verify so a blocked
    // instance doesn't burn RSA cycles.
    let actor_url = strip_keyid_fragment(&ctx.key_id);
    if state.denylist.is_blocked_actor(&actor_url).await {
        return Err(InboxError::forbidden(DropReason::Denylisted(actor_url)));
    }

    // Gate 2b: HTTP Signature verification.
    let pubkey_pem = state
        .webfinger
        .resolve_pubkey_pem(&ctx.key_id)
        .await
        .map_err(|err| match err {
            WebFingerError::NotFound(_)
            | WebFingerError::Malformed(_)
            | WebFingerError::Network(_) => {
                InboxError::unauthorized(DropReason::WebFingerLookupFailed)
            }
        })?;

    let scheme = verify_inbox_request(&pubkey_pem, &ctx, &body).map_err(|reason| match reason {
        DropReason::UnsupportedAlgorithm => InboxError::forbidden(reason),
        _ => InboxError::unauthorized(reason),
    })?;

    // Gate 3: replay window. Run AFTER signature verify so a forged
    // (Digest, Date) pair from an unauthenticated attacker can't
    // poison the cache against a real future activity.
    let replay_key = (ctx.digest.clone(), date_to_unix(&ctx.date));
    if !state.replay.record_and_check_now(replay_key) {
        return Err(InboxError::unauthorized(DropReason::Replay));
    }

    // All gates passed — enqueue.
    let delivery = PendingDelivery {
        actor_url,
        scheme,
        body: body.to_vec(),
        received_at: SystemTime::now(),
    };
    state
        .sink
        .enqueue(delivery)
        .await
        .map_err(|()| InboxError::service_unavailable(DropReason::SinkRejected))?;

    Ok(())
}

/// Parse the instance hostname (host[:port]) from a signing actor
/// `keyId` URL. The token bucket keys on this so a single hostile
/// instance burns its own budget across all its actors.
fn parse_instance(key_id: &str) -> Option<String> {
    let url = url::Url::parse(key_id).ok()?;
    let host = url.host_str()?.to_string();
    match url.port() {
        Some(port) => Some(format!("{host}:{port}")),
        None => Some(host),
    }
}

/// Strip the `#main-key` (or any other) fragment from a `keyId` URL
/// to recover the bare actor URL — what the denylist consults.
fn strip_keyid_fragment(key_id: &str) -> String {
    match key_id.find('#') {
        Some(idx) => key_id[..idx].to_string(),
        None => key_id.to_string(),
    }
}

/// Convert an IMF-fixdate `Date` header to Unix seconds. Falls back
/// to `0` if parse fails — replay-key collisions on `0` are
/// vanishingly improbable and the prior `check_date_skew` already
/// rejected unparseable inputs, so this is just a defensive default.
fn date_to_unix(date: &str) -> i64 {
    super::sig_verify::parse_imf_fixdate(date).map_or(0, |t| {
        i64::try_from(
            t.duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        )
        .unwrap_or(0)
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::inbox::{InboxDenylistCheck, PendingDeliverySink, WebFingerError, WebFingerLookup};
    use async_trait::async_trait;
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use rsa::rand_core::OsRng;
    use rsa::RsaPrivateKey;
    use std::sync::Mutex;

    struct NoopDenylist;
    #[async_trait]
    impl InboxDenylistCheck for NoopDenylist {
        async fn is_blocked_actor(&self, _: &str) -> bool {
            false
        }
    }

    struct AlwaysDenyDenylist;
    #[async_trait]
    impl InboxDenylistCheck for AlwaysDenyDenylist {
        async fn is_blocked_actor(&self, _: &str) -> bool {
            true
        }
    }

    struct StubWebFinger {
        pem: String,
    }
    #[async_trait]
    impl WebFingerLookup for StubWebFinger {
        async fn resolve_pubkey_pem(&self, _: &str) -> Result<String, WebFingerError> {
            Ok(self.pem.clone())
        }
        async fn invalidate(&self, _: &str) {}
    }

    struct MissingWebFinger;
    #[async_trait]
    impl WebFingerLookup for MissingWebFinger {
        async fn resolve_pubkey_pem(&self, _: &str) -> Result<String, WebFingerError> {
            Err(WebFingerError::NotFound("x".into()))
        }
        async fn invalidate(&self, _: &str) {}
    }

    #[derive(Default)]
    struct RecordingSink {
        deliveries: Mutex<Vec<PendingDelivery>>,
    }
    #[async_trait]
    impl PendingDeliverySink for RecordingSink {
        async fn enqueue(&self, delivery: PendingDelivery) -> Result<(), ()> {
            self.deliveries.lock().unwrap().push(delivery);
            Ok(())
        }
    }

    fn keypair_pem() -> (String, String) {
        let priv_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let pub_key = priv_key.to_public_key();
        let priv_pem = priv_key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let pub_pem = pub_key.to_public_key_pem(LineEnding::LF).unwrap();
        (priv_pem, pub_pem)
    }

    fn make_state(pub_pem: String, sink: Arc<RecordingSink>) -> InboxState {
        InboxState::builder(
            Arc::new(NoopDenylist),
            Arc::new(StubWebFinger { pem: pub_pem }),
            sink,
        )
        .build()
    }

    #[test]
    fn parse_instance_extracts_hostname() {
        assert_eq!(
            parse_instance("https://mastodon.example/actors/josh#main-key").as_deref(),
            Some("mastodon.example")
        );
    }

    #[test]
    fn parse_instance_preserves_non_default_port() {
        assert_eq!(
            parse_instance("https://mastodon.example:8443/actors/josh#main-key").as_deref(),
            Some("mastodon.example:8443")
        );
    }

    #[test]
    fn parse_instance_rejects_non_url() {
        assert!(parse_instance("not-a-url").is_none());
    }

    #[test]
    fn strip_keyid_fragment_drops_fragment() {
        assert_eq!(
            strip_keyid_fragment("https://etchit.io/actors/josh#main-key"),
            "https://etchit.io/actors/josh"
        );
    }

    #[test]
    fn strip_keyid_fragment_is_noop_when_no_fragment() {
        assert_eq!(
            strip_keyid_fragment("https://etchit.io/actors/josh"),
            "https://etchit.io/actors/josh"
        );
    }

    // ---- End-to-end gate orchestration tests (no real HTTP). ----

    use fetchit_fedi::signature::HttpSignatureKey;

    fn signed_headers_for(
        priv_pem: &str,
        body: &[u8],
        key_id: &str,
        url: &url::Url,
        date: &str,
    ) -> HeaderMap {
        let key = HttpSignatureKey {
            key_id: key_id.to_string(),
            rsa_private_pem: priv_pem.to_string(),
        };
        let now_unix = i64::try_from(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let signed = key.sign_post_rfc9421(url, body, date, now_unix).unwrap();

        let mut h = HeaderMap::new();
        h.insert("host", url.host_str().unwrap().parse().unwrap());
        h.insert("date", signed.date.parse().unwrap());
        h.insert("content-digest", signed.content_digest.parse().unwrap());
        h.insert("signature-input", signed.signature_input.parse().unwrap());
        h.insert("signature", signed.signature.parse().unwrap());
        h
    }

    fn now_imf_fixdate() -> String {
        // Build a Date header for "now" via the fetchit-fedi
        // formatter so the parse_imf_fixdate round-trips in the
        // date-skew check.
        fetchit_fedi::transport::format_imf_fixdate(SystemTime::now())
    }

    #[tokio::test]
    async fn happy_path_accepts_well_formed_post() {
        let (priv_pem, pub_pem) = keypair_pem();
        let sink = Arc::new(RecordingSink::default());
        let state = make_state(pub_pem, sink.clone());
        let body = br#"{"type":"Create","actor":"https://etchit.io/actors/josh"}"#;
        let date = now_imf_fixdate();
        let url: url::Url = "https://relay.example/inbox".parse().unwrap();
        let headers = signed_headers_for(
            &priv_pem,
            body,
            "https://etchit.io/actors/josh#main-key",
            &url,
            &date,
        );

        handle_inbox_inner(state, headers, Bytes::from_static(body))
            .await
            .expect("happy path");
        assert_eq!(sink.deliveries.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn body_too_large_rejected_before_signature_verify() {
        let (_priv_pem, pub_pem) = keypair_pem();
        let sink = Arc::new(RecordingSink::default());
        let state = InboxState::builder(
            Arc::new(NoopDenylist),
            Arc::new(StubWebFinger { pem: pub_pem }),
            sink.clone(),
        )
        .with_max_body_bytes(64)
        .build();

        // Body bigger than cap; signature headers absent — we should
        // hit the body-size gate first.
        let headers = HeaderMap::new();
        let body = vec![0u8; 128];
        let err = handle_inbox_inner(state, headers, Bytes::from(body))
            .await
            .unwrap_err();
        assert!(matches!(err.reason, DropReason::BodyTooLarge));
        assert_eq!(err.status, 413);
        assert!(sink.deliveries.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn missing_signature_header_rejected_with_400() {
        let (_priv_pem, pub_pem) = keypair_pem();
        let sink = Arc::new(RecordingSink::default());
        let state = make_state(pub_pem, sink);
        let headers = HeaderMap::new(); // no headers
        let body = b"{}";

        let err = handle_inbox_inner(state, headers, Bytes::from_static(body))
            .await
            .unwrap_err();
        assert!(matches!(err.reason, DropReason::MissingHeader(_)));
        assert_eq!(err.status, 400);
    }

    #[tokio::test]
    async fn stale_date_rejected_with_400() {
        let (priv_pem, pub_pem) = keypair_pem();
        let sink = Arc::new(RecordingSink::default());
        let state = make_state(pub_pem, sink.clone());
        let body = b"{}";
        // 1995-era Date — long past the 5-min skew.
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";
        let url: url::Url = "https://relay.example/inbox".parse().unwrap();
        let headers = signed_headers_for(
            &priv_pem,
            body,
            "https://etchit.io/actors/josh#main-key",
            &url,
            date,
        );

        let err = handle_inbox_inner(state, headers, Bytes::from_static(body))
            .await
            .unwrap_err();
        assert!(matches!(err.reason, DropReason::StaleRequest));
        assert_eq!(err.status, 400);
        assert!(sink.deliveries.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn rate_limit_rejects_when_instance_drains_bucket() {
        let (priv_pem, pub_pem) = keypair_pem();
        let sink = Arc::new(RecordingSink::default());
        // Bucket of 1 token: first request burns it, second must 429.
        let state = InboxState::builder(
            Arc::new(NoopDenylist),
            Arc::new(StubWebFinger { pem: pub_pem }),
            sink.clone(),
        )
        .with_rate_limit(Arc::new(InboxRateLimit::new(1)))
        .build();
        let body = b"{}";
        let date = now_imf_fixdate();
        let url: url::Url = "https://relay.example/inbox".parse().unwrap();
        let headers = signed_headers_for(
            &priv_pem,
            body,
            "https://etchit.io/actors/josh#main-key",
            &url,
            &date,
        );

        // First request: success.
        handle_inbox_inner(state.clone(), headers.clone(), Bytes::from_static(body))
            .await
            .expect("first request fits in bucket");
        // Second request from the same instance: 429. The replay
        // window would also reject this on the 3rd gate, but rate
        // limit runs FIRST so we expect the rate-limit reason.
        // We sign a DIFFERENT body so the replay key differs.
        let body2 = b"{\"x\":1}";
        let headers2 = signed_headers_for(
            &priv_pem,
            body2,
            "https://etchit.io/actors/josh#main-key",
            &url,
            &date,
        );
        let err = handle_inbox_inner(state, headers2, Bytes::from_static(body2))
            .await
            .unwrap_err();
        assert!(
            matches!(err.reason, DropReason::RateLimited(_)),
            "got: {:?}",
            err.reason
        );
        assert_eq!(err.status, 429);
    }

    #[tokio::test]
    async fn denylisted_actor_rejected_with_403() {
        let (priv_pem, pub_pem) = keypair_pem();
        let sink = Arc::new(RecordingSink::default());
        let state = InboxState::builder(
            Arc::new(AlwaysDenyDenylist),
            Arc::new(StubWebFinger { pem: pub_pem }),
            sink.clone(),
        )
        .build();
        let body = b"{}";
        let date = now_imf_fixdate();
        let url: url::Url = "https://relay.example/inbox".parse().unwrap();
        let headers = signed_headers_for(
            &priv_pem,
            body,
            "https://attacker.example/actors/eve#main-key",
            &url,
            &date,
        );

        let err = handle_inbox_inner(state, headers, Bytes::from_static(body))
            .await
            .unwrap_err();
        assert!(matches!(err.reason, DropReason::Denylisted(_)));
        assert_eq!(err.status, 403);
        assert!(sink.deliveries.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn webfinger_failure_rejected_with_401() {
        let (priv_pem, _) = keypair_pem();
        let sink = Arc::new(RecordingSink::default());
        let state = InboxState::builder(
            Arc::new(NoopDenylist),
            Arc::new(MissingWebFinger),
            sink.clone(),
        )
        .build();
        let body = b"{}";
        let date = now_imf_fixdate();
        let url: url::Url = "https://relay.example/inbox".parse().unwrap();
        let headers = signed_headers_for(
            &priv_pem,
            body,
            "https://etchit.io/actors/josh#main-key",
            &url,
            &date,
        );

        let err = handle_inbox_inner(state, headers, Bytes::from_static(body))
            .await
            .unwrap_err();
        assert!(matches!(err.reason, DropReason::WebFingerLookupFailed));
        assert_eq!(err.status, 401);
    }

    #[tokio::test]
    async fn tampered_body_rejected_with_digest_mismatch() {
        let (priv_pem, pub_pem) = keypair_pem();
        let sink = Arc::new(RecordingSink::default());
        let state = make_state(pub_pem, sink.clone());
        let signed_body = br#"{"type":"Create"}"#;
        let date = now_imf_fixdate();
        let url: url::Url = "https://relay.example/inbox".parse().unwrap();
        let headers = signed_headers_for(
            &priv_pem,
            signed_body,
            "https://etchit.io/actors/josh#main-key",
            &url,
            &date,
        );

        // Receiver gets a TAMPERED body but the same headers — the
        // signature-verify gate's digest check catches it.
        let tampered = br#"{"type":"Hostile"}"#;
        let err = handle_inbox_inner(state, headers, Bytes::from_static(tampered))
            .await
            .unwrap_err();
        assert!(matches!(err.reason, DropReason::SigFail(_)));
        assert_eq!(err.status, 401);
        assert!(sink.deliveries.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn replay_rejects_second_identical_post() {
        let (priv_pem, pub_pem) = keypair_pem();
        let sink = Arc::new(RecordingSink::default());
        // Give the rate-limit room (2 tokens) so the rate-limit gate
        // doesn't preempt the replay gate.
        let state = InboxState::builder(
            Arc::new(NoopDenylist),
            Arc::new(StubWebFinger { pem: pub_pem }),
            sink.clone(),
        )
        .with_rate_limit(Arc::new(InboxRateLimit::new(10)))
        .build();
        let body = b"{}";
        let date = now_imf_fixdate();
        let url: url::Url = "https://relay.example/inbox".parse().unwrap();
        let headers = signed_headers_for(
            &priv_pem,
            body,
            "https://etchit.io/actors/josh#main-key",
            &url,
            &date,
        );

        handle_inbox_inner(state.clone(), headers.clone(), Bytes::from_static(body))
            .await
            .expect("first request");
        let err = handle_inbox_inner(state, headers, Bytes::from_static(body))
            .await
            .unwrap_err();
        assert!(matches!(err.reason, DropReason::Replay));
        assert_eq!(err.status, 401);
        // Only the first delivery should have made it to the sink.
        assert_eq!(sink.deliveries.lock().unwrap().len(), 1);
    }
}
