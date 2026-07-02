//! Top-level [`Server`] type — wires state, routes, and the background sweeper.

use crate::auth::AuthService;
use crate::blob::{get_blob, post_blob, BlobStore};
use crate::capability::CapabilityResolver;
use crate::config::ServerConfig;
use crate::forwarding::{get_forwarding, post_forwarding, ForwardingIndex};
#[cfg(feature = "fediverse-inbox")]
use crate::inbox::{inbox_router, InboxMetrics, InboxState};
use crate::metrics::Metrics;
use crate::pair_record::{
    get_pair_record, get_pair_record_v4, post_pair_record, post_pair_record_v4, PairRecordIndex,
};
use crate::profile::{delete_profile, get_profile, post_profile, ProfileIndex};
use crate::ratelimit::RateLimiter;
#[cfg(feature = "fediverse-inbox")]
use crate::registry::{registry_router, RegistryState};
use crate::session::SessionRegistry;
use crate::signature::{MlDsa65Verifier, SignatureVerifier};
use crate::transit::TransitBuffer;
use crate::ws::ws_handler;
use anyhow::Result;
use axum::extract::{DefaultBodyLimit, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use fetchit_relay_proto::{AuthChallenge, AuthVerifyRequest, AuthVerifyResponse, Region};
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{info, warn};

/// Shared state passed to every axum handler.
pub struct ServerState {
    /// Operating config.
    pub config: ServerConfig,
    /// Challenge / bearer service.
    pub auth: Arc<AuthService>,
    /// In-RAM transit buffer.
    pub transit: Arc<TransitBuffer>,
    /// Live-connection registry.
    pub sessions: Arc<SessionRegistry>,
    /// ML-DSA-65 signature backend.
    pub verifier: Arc<dyn SignatureVerifier>,
    /// Capability token validator.
    pub capability_resolver: Arc<CapabilityResolver>,
    /// Per-agent rate limiter.
    pub ratelimit: Arc<RateLimiter>,
    /// Allow-listed Prometheus counters.
    pub metrics: Arc<Metrics>,
    /// In-RAM profile-index map (`agent_id` → latest record). See
    /// `docs/profile-manifest-v1.md` § 4 + `docs/qr-pairing-v1.md`.
    pub profiles: Arc<ProfileIndex>,
    /// In-RAM pair-record index (`agent_id` → latest signed reachability
    /// pointer). Reachability V1 / TB1.
    pub pair_records: Arc<PairRecordIndex>,
    /// In-RAM sealed-blob store (`token` → opaque ciphertext, TTL'd) for
    /// pointer-URI transports: link-device enrollment offers and group
    /// invites carry a token, the sealed payload rides here.
    pub blobs: Arc<BlobStore>,
    /// In-RAM forwarding index (`agent_id` → signed relay redirect), TTL
    /// swept. Reachability V1 / TB2.
    pub forwarding: Arc<ForwardingIndex>,
    /// Optional shared [`InboxMetrics`] when the relay-server is
    /// built with `--features fediverse-inbox`. When `Some`, the
    /// `/v1/metrics` endpoint splices the inbox counter family into
    /// its output. Callers attach the same `Arc<InboxMetrics>` to
    /// the inbox handler's `InboxState` so handler increments and
    /// scrape reads observe the same atomic counters.
    #[cfg(feature = "fediverse-inbox")]
    pub inbox_metrics: Option<Arc<InboxMetrics>>,
}

/// Builder + runner for one relay node.
pub struct Server {
    config: ServerConfig,
    verifier: Arc<dyn SignatureVerifier>,
    /// The live-connection registry, created at [`Server::new`] so a
    /// production inbox delivery sink can be wired to the SAME registry
    /// the WebSocket handler registers sessions into (see
    /// [`Server::sessions`] / [`Server::with_inbox`]).
    sessions: Arc<SessionRegistry>,
    #[cfg(feature = "fediverse-inbox")]
    inbox_metrics: Option<Arc<InboxMetrics>>,
    /// Fully-configured inbox state when an operator opts in via
    /// [`Server::with_inbox`]. When `Some`, [`Server::router`] mounts
    /// the `POST /inbox` route and splices the state's `InboxMetrics`
    /// into `/v1/metrics`. `None` (the default) leaves the route
    /// structurally absent.
    #[cfg(feature = "fediverse-inbox")]
    inbox: Option<InboxState>,
    /// Fully-configured registry + serving state when an operator opts
    /// in. When `Some`, [`Server::router`] merges the registry router
    /// (POST/PUT `/v1/actors`, `WebFinger` server, actor-doc GET).
    #[cfg(feature = "fediverse-inbox")]
    registry: Option<RegistryState>,
}

impl Server {
    /// Construct a new server with the production verifier.
    #[must_use]
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            verifier: Arc::new(MlDsa65Verifier::new()),
            sessions: Arc::new(SessionRegistry::new()),
            #[cfg(feature = "fediverse-inbox")]
            inbox_metrics: None,
            #[cfg(feature = "fediverse-inbox")]
            inbox: None,
            #[cfg(feature = "fediverse-inbox")]
            registry: None,
        }
    }

    /// The live-connection registry this server registers WebSocket
    /// sessions into.
    ///
    /// Build a production inbox delivery sink
    /// ([`crate::inbox::SessionBroadcastSink`]) from this same `Arc`
    /// before calling [`Server::with_inbox`], so a broadcast
    /// `EnvelopeKind::PublicPost` reaches the sessions the server
    /// actually serves.
    #[must_use]
    pub fn sessions(&self) -> Arc<SessionRegistry> {
        self.sessions.clone()
    }

    /// Inject a custom verifier (e.g. `AcceptAllVerifier` in tests).
    #[must_use]
    pub fn with_verifier(mut self, verifier: Arc<dyn SignatureVerifier>) -> Self {
        self.verifier = verifier;
        self
    }

    /// Attach a shared [`InboxMetrics`] so `/v1/metrics` also renders
    /// the `fedi_inbox_*_total` counter family. The same `Arc` should
    /// be threaded into the inbox handler's
    /// `crate::inbox::InboxState::metrics` so handler increments and
    /// scrape reads observe the same atomics.
    ///
    /// Only available when the `fediverse-inbox` feature is enabled.
    #[cfg(feature = "fediverse-inbox")]
    #[must_use]
    pub fn with_inbox_metrics(mut self, metrics: Arc<InboxMetrics>) -> Self {
        self.inbox_metrics = Some(metrics);
        self
    }

    /// Mount the fediverse `POST /inbox` endpoint, wiring `state`'s
    /// gate pipeline + delivery sink onto the public router, and
    /// splice `state`'s [`InboxMetrics`] into `/v1/metrics` so handler
    /// increments and scrape reads observe the same atomics (no
    /// separate [`Server::with_inbox_metrics`] call needed).
    ///
    /// The default relay build never calls this, so the route is
    /// structurally absent — a `POST /inbox` returns 404 unless an
    /// operator opts in. Only available when the `fediverse-inbox`
    /// feature is enabled.
    #[cfg(feature = "fediverse-inbox")]
    #[must_use]
    pub fn with_inbox(mut self, state: InboxState) -> Self {
        self.inbox = Some(state);
        self
    }

    /// Mount the M5.1 registry + serving endpoints (POST/PUT
    /// `/v1/actors`, `GET /.well-known/webfinger`, `GET /actors/<h>`)
    /// from `state`. The default relay build never calls this, so the
    /// routes are structurally absent. Only available when the
    /// `fediverse-inbox` feature is enabled.
    #[cfg(feature = "fediverse-inbox")]
    #[must_use]
    pub fn with_registry(mut self, state: RegistryState) -> Self {
        self.registry = Some(state);
        self
    }

    /// Assemble the axum router and shared state, consuming `self`.
    pub fn router(self) -> (Router, Arc<ServerState>) {
        let metrics = Arc::new(Metrics::new(
            self.config.region.clone(),
            self.config.server_version.clone(),
        ));
        // An attached inbox is BOTH the `/inbox` route source and the
        // `/v1/metrics` splice source — its `InboxMetrics` is the same
        // `Arc` the handler increments. Fall back to a metrics-only
        // attachment (`with_inbox_metrics`) when no full inbox state
        // was provided.
        #[cfg(feature = "fediverse-inbox")]
        let inbox = self.inbox;
        #[cfg(feature = "fediverse-inbox")]
        let registry = self.registry;
        #[cfg(feature = "fediverse-inbox")]
        let inbox_metrics = inbox
            .as_ref()
            .map(|s| s.metrics.clone())
            .or(self.inbox_metrics);
        let state = Arc::new(ServerState {
            auth: Arc::new(AuthService::new(
                self.config.challenge_ttl,
                self.config.bearer_ttl,
            )),
            transit: Arc::new(TransitBuffer::new(
                self.config.transit_ttl,
                self.config.transit_per_recipient,
                self.config.transit_total_bytes_cap,
            )),
            sessions: self.sessions,
            verifier: self.verifier,
            capability_resolver: Arc::new(CapabilityResolver::new(self.config.issuer_keys.clone())),
            ratelimit: Arc::new(RateLimiter::new()),
            metrics,
            profiles: ProfileIndex::new(),
            pair_records: PairRecordIndex::new(),
            blobs: BlobStore::new(),
            forwarding: ForwardingIndex::new(),
            config: self.config,
            #[cfg(feature = "fediverse-inbox")]
            inbox_metrics,
        });
        #[allow(unused_mut)]
        let mut router = Router::new()
            .route("/v1/health", get(health))
            .route("/v1/metrics", get(metrics_handler))
            .route("/v1/auth/challenge", post(auth_challenge))
            .route("/v1/auth/verify", post(auth_verify))
            .route("/v1/ws", get(ws_handler))
            .route("/v1/profile", post(post_profile))
            .route(
                "/v1/profile/:agent_id",
                get(get_profile).delete(delete_profile),
            )
            .route("/v1/pair-record", post(post_pair_record))
            .route("/v1/pair-record/:agent_id", get(get_pair_record))
            .route("/v1/pair-record-v4", post(post_pair_record_v4))
            .route("/v1/pair-record-v4/:user_id", get(get_pair_record_v4))
            .route(
                "/v1/blob/:token",
                post(post_blob)
                    .get(get_blob)
                    .layer(DefaultBodyLimit::max(crate::blob::MAX_BLOB_BYTES)),
            )
            .route("/v1/forwarding", post(post_forwarding))
            .route("/v1/forwarding/:agent_id", get(get_forwarding))
            .with_state(state.clone());
        // Mount the opt-in fediverse inbox last so it composes onto the
        // fully-stated base router (both are `Router<()>`). Absent by
        // default — see [`Server::with_inbox`].
        #[cfg(feature = "fediverse-inbox")]
        if let Some(inbox_state) = inbox {
            router = router.merge(inbox_router(inbox_state));
        }
        #[cfg(feature = "fediverse-inbox")]
        if let Some(registry_state) = registry {
            router = router.merge(registry_router(registry_state));
        }
        (router, state)
    }

    /// Build the internal-only router served on the loopback listener.
    ///
    /// Hosts `/v1/metrics/internal` — a separate channel for aggregates
    /// the public scrape must not expose. Today the body is identical
    /// to `/v1/metrics`; future sensitive counters
    /// (`profile_index_size`, denylist-health, agent-id cardinality)
    /// land here without re-shaping the public surface.
    ///
    /// Defense-in-depth: the route is structurally absent from the
    /// public router, so even if loopback binding were misconfigured a
    /// request to `/v1/metrics/internal` on the public listener returns
    /// 404. The kernel-level loopback bind is the primary boundary; the
    /// route-absence is the secondary.
    pub fn internal_router(state: Arc<ServerState>) -> Router {
        Router::new()
            .route("/v1/metrics/internal", get(metrics_internal_handler))
            .with_state(state)
    }

    /// Bind, spawn the background sweeper, and serve forever.
    ///
    /// Also binds the loopback-only internal listener when
    /// `config.internal_bind` is `Some`. A non-loopback internal bind
    /// is refused before the listener is opened — defense in depth on
    /// top of `ServerConfig::from_env`'s validation, in case the config
    /// was constructed in code rather than from environment.
    ///
    /// # Errors
    /// Returns any IO error from binding or serving, or
    /// `anyhow::Error` when `internal_bind` is set to a non-loopback
    /// address.
    pub async fn run(self) -> Result<()> {
        let bind = self.config.bind;
        let region = self.config.region.clone();
        let internal_bind = self.config.internal_bind;
        // Validate the internal-bind loopback constraint before any
        // listener bind or background task spawn. A non-loopback bind
        // must be refused without leaking the sweeper task that would
        // otherwise outlive the failed `run()` call.
        if let Some(internal) = internal_bind {
            if !internal.ip().is_loopback() {
                anyhow::bail!(
                    "internal bind must be loopback (127.0.0.0/8 or ::1), got {internal}"
                );
            }
        }
        let (router, state) = self.router();
        let listener = TcpListener::bind(bind).await?;
        info!(%bind, %region, "fetchit-relay-server listening");
        spawn_sweeper(state.clone());
        if let Some(internal) = internal_bind {
            let internal_listener = TcpListener::bind(internal).await?;
            let actual = internal_listener.local_addr().unwrap_or(internal);
            info!(%actual, "internal-metrics listener bound (loopback only)");
            let internal_router = Self::internal_router(state);
            tokio::spawn(async move {
                if let Err(e) = axum::serve(internal_listener, internal_router).await {
                    warn!(error = ?e, "internal-metrics listener exited");
                }
            });
        }
        // `into_make_service_with_connect_info` populates `ConnectInfo<SocketAddr>`
        // so the registry rate limiter's peer fallback is live when the
        // CF-set `x-real-ip` header is absent (Alice F1); without it every
        // header-less request collapses to one shared bucket.
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await?;
        Ok(())
    }
}

fn spawn_sweeper(state: Arc<ServerState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        // Only warn when the eviction count STRICTLY EXCEEDS the
        // previous sweep — a persistently-offline recipient would
        // otherwise flood logs at 2 warns/min indefinitely. Bob's
        // dashboard scrapes the metric (`transit_buffer_envelopes`)
        // for steady-state; the warn is for spike detection.
        let mut last_evicted: usize = 0;
        loop {
            interval.tick().await;
            let evicted = state.transit.sweep_expired();
            let _ = state.auth.sweep_expired();
            state.ratelimit.sweep_idle(Duration::from_secs(3600));
            // Reachability V1 / TB2: drop forwarding pointers past their
            // ~30-day TTL. RAM-only, no metric — a forwarding record is a
            // transitional aid, not a tracked steady-state resource.
            let _ = state.forwarding.sweep_expired(crate::forwarding::now_ms());
            // Reclaim expired sealed blobs whose token was never GET, so a
            // write-only token flood cannot grow RAM unbounded (lazy
            // expiry-on-read alone would never evict a never-read blob).
            let _ = state.blobs.sweep_expired(crate::blob::now_ms());
            let buffered = i64::try_from(state.transit.len()).unwrap_or(i64::MAX);
            state.metrics.set_transit_buffer_envelopes(buffered);
            // Count every TTL-evicted envelope into the dropped-by-TTL
            // counter so operators get a scrape-able cross-relay
            // dead-drop signal independent of the log spike warn.
            state
                .metrics
                .envelopes_dropped_ttl(u64::try_from(evicted).unwrap_or(u64::MAX));
            if evicted > last_evicted {
                warn!(
                    evicted,
                    transit_buffer = buffered,
                    "sweeper: transit-eviction count climbed; recipients failing to drain",
                );
            }
            last_evicted = evicted;
        }
    });
}

/// Health endpoint payload.
#[derive(Debug, Serialize)]
pub struct Health {
    /// Always `true` while serving.
    pub ok: bool,
    /// Server build identifier.
    pub version: String,
    /// Geographic region tag.
    pub region: Region,
    /// Currently-connected agent count.
    pub connections: usize,
}

async fn health(State(state): State<Arc<ServerState>>) -> Json<Health> {
    Json(Health {
        ok: true,
        version: state.config.server_version.clone(),
        region: state.config.region.clone(),
        connections: state.sessions.connection_count(),
    })
}

async fn metrics_handler(
    State(state): State<Arc<ServerState>>,
) -> impl axum::response::IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        render_metrics_body(&state),
    )
}

async fn metrics_internal_handler(
    State(state): State<Arc<ServerState>>,
) -> impl axum::response::IntoResponse {
    // Body parity with /v1/metrics today; future loopback-only
    // counters (profile_index_size, denylist health, agent-id
    // cardinality) get added here without re-shaping the public
    // surface.
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        render_metrics_body(&state),
    )
}

/// Render the full `/v1/metrics` body. Concatenates the existing
/// relay-server counter family with the inbox counter family when
/// the `fediverse-inbox` feature is enabled AND a shared
/// `InboxMetrics` was attached via [`Server::with_inbox_metrics`].
///
/// Stage 3.3a (M4) — keeps the metrics-source composition local to
/// `server.rs` so the inbox module stays a pure observability
/// producer.
fn render_metrics_body(state: &ServerState) -> String {
    #[allow(unused_mut)]
    let mut body = state.metrics.render_prometheus();
    #[cfg(feature = "fediverse-inbox")]
    if let Some(m) = &state.inbox_metrics {
        body.push_str(&m.render_prometheus());
    }
    body
}

async fn auth_challenge(State(state): State<Arc<ServerState>>) -> Json<AuthChallenge> {
    state.metrics.auth_challenge_issued();
    Json(state.auth.issue_challenge())
}

async fn auth_verify(
    State(state): State<Arc<ServerState>>,
    Json(req): Json<AuthVerifyRequest>,
) -> Result<Json<AuthVerifyResponse>, (axum::http::StatusCode, String)> {
    match state.auth.verify(req, state.verifier.as_ref()) {
        Ok(resp) => {
            state.metrics.auth_verify_ok();
            Ok(Json(resp))
        }
        Err(e) => {
            state.metrics.auth_verify_failed();
            warn!(error = ?e, "auth_verify rejected");
            Err((
                axum::http::StatusCode::UNAUTHORIZED,
                "authentication failed".to_owned(),
            ))
        }
    }
}

#[cfg(all(test, feature = "fediverse-inbox"))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod fediverse_inbox_metrics_tests {
    use super::*;
    use crate::inbox::{DropReason, InboxMetrics};

    fn test_server_state(inbox_metrics: Option<Arc<InboxMetrics>>) -> Arc<ServerState> {
        // Build a Server with a minimal config and surface the
        // ServerState via router().1 — the router itself is dropped.
        let bind = "127.0.0.1:0".parse().unwrap();
        let server = Server::new(ServerConfig::defaults(bind, Region::Other("test".into())))
            .with_verifier(Arc::new(crate::signature::AcceptAllVerifier));
        let server = match inbox_metrics {
            Some(m) => server.with_inbox_metrics(m),
            None => server,
        };
        let (_router, state) = server.router();
        state
    }

    #[test]
    fn metrics_body_omits_inbox_section_when_no_metrics_attached() {
        let state = test_server_state(None);
        let body = render_metrics_body(&state);
        assert!(
            !body.contains("fedi_inbox_"),
            "inbox section must NOT appear when no InboxMetrics attached:\n{body}"
        );
    }

    #[test]
    fn metrics_body_includes_inbox_section_when_attached() {
        let im = Arc::new(InboxMetrics::new());
        im.record_accept();
        im.record_drop(&DropReason::BodyTooLarge);
        let state = test_server_state(Some(im));
        let body = render_metrics_body(&state);
        // Existing relay-server counter family still present.
        assert!(body.contains("# HELP"), "expected relay counter HELP lines");
        // Inbox family spliced in.
        assert!(
            body.contains("fedi_inbox_accepted_total 1"),
            "expected spliced inbox accepted counter:\n{body}"
        );
        assert!(
            body.contains("fedi_inbox_dropped_body_too_large_total 1"),
            "expected spliced inbox drop counter:\n{body}"
        );
    }

    #[tokio::test]
    async fn v1_metrics_endpoint_serves_spliced_body() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt as _;

        let im = Arc::new(InboxMetrics::new());
        im.record_accept();
        let bind = "127.0.0.1:0".parse().unwrap();
        let server = Server::new(ServerConfig::defaults(bind, Region::Other("test".into())))
            .with_verifier(Arc::new(crate::signature::AcceptAllVerifier))
            .with_inbox_metrics(im);
        let (router, _state) = server.router();

        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/v1/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let body_bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(status.is_success(), "status was {status}");
        assert!(body.contains("fedi_inbox_accepted_total 1"));
    }
}

/// Stage 3.3b — `Server::with_inbox` mounts the `POST /inbox` route on
/// the live router. These drive real HTTP through the mounted router
/// (via `tower::oneshot`) to prove the endpoint is reachable, runs the
/// gate pipeline, is absent by default, and auto-splices its metrics.
#[cfg(all(test, feature = "fediverse-inbox"))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod inbox_mount_tests {
    use super::*;
    use crate::inbox::{
        InboxDenylistCheck, PendingDelivery, PendingDeliverySink, WebFingerError, WebFingerLookup,
    };
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use rsa::rand_core::OsRng;
    use rsa::RsaPrivateKey;
    use std::sync::Mutex;
    use std::time::SystemTime;
    use tower::ServiceExt as _;

    struct NoopDenylist;
    #[async_trait]
    impl InboxDenylistCheck for NoopDenylist {
        async fn is_blocked_actor(&self, _: &str) -> bool {
            false
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

    fn test_router(state: InboxState) -> Router {
        let bind = "127.0.0.1:0".parse().unwrap();
        Server::new(ServerConfig::defaults(bind, Region::Other("test".into())))
            .with_verifier(Arc::new(crate::signature::AcceptAllVerifier))
            .with_inbox(state)
            .router()
            .0
    }

    /// Build a fully-signed `POST /inbox` request for the mounted route.
    fn signed_post(priv_pem: &str, body: &[u8], key_id: &str, url: &url::Url) -> Request<Body> {
        use fetchit_fedi::signature::HttpSignatureKey;
        let date = fetchit_fedi::transport::format_imf_fixdate(SystemTime::now());
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
        let signed = key.sign_post_rfc9421(url, body, &date, now_unix).unwrap();
        Request::builder()
            .method("POST")
            .uri("/inbox")
            .header("host", url.host_str().unwrap())
            .header("date", signed.date)
            .header("content-digest", signed.content_digest)
            .header("signature-input", signed.signature_input)
            .header("signature", signed.signature)
            .body(Body::from(body.to_vec()))
            .unwrap()
    }

    #[tokio::test]
    async fn mounted_inbox_accepts_signed_post_with_202() {
        let (priv_pem, pub_pem) = keypair_pem();
        let sink = Arc::new(RecordingSink::default());
        let state = InboxState::builder(
            Arc::new(NoopDenylist),
            Arc::new(StubWebFinger { pem: pub_pem }),
            sink.clone(),
        )
        .build();
        let router = test_router(state);

        let body = br#"{"type":"Create","actor":"https://etchit.io/actors/josh"}"#;
        let url: url::Url = "https://relay.example/inbox".parse().unwrap();
        let req = signed_post(
            &priv_pem,
            body,
            "https://etchit.io/actors/josh#main-key",
            &url,
        );

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        assert_eq!(sink.deliveries.lock().unwrap().len(), 1);
    }

    /// End-to-end #200 vertical slice: a signed `POST /inbox` that
    /// passes every gate is fanned out by the production
    /// `SessionBroadcastSink` — wired to the server's OWN registry via
    /// `Server::sessions()` — to a live connected session as a
    /// canonical-attribution `EnvelopeKind::PublicPost`.
    #[tokio::test]
    async fn mounted_inbox_broadcasts_public_post_to_connected_session() {
        use crate::inbox::SessionBroadcastSink;
        use fetchit_relay_proto::{AgentId, EnvelopeKind, PublicPostPayload, ServerFrame};
        use tokio::sync::mpsc;

        let (priv_pem, pub_pem) = keypair_pem();

        // Build the server first so the sink shares its registry, then
        // register a fake connected session on that same registry.
        let bind = "127.0.0.1:0".parse().unwrap();
        let server = Server::new(ServerConfig::defaults(bind, Region::Other("test".into())))
            .with_verifier(Arc::new(crate::signature::AcceptAllVerifier));
        let sessions = server.sessions();
        let (tx, mut rx) = mpsc::channel(8);
        let _id = sessions.register(AgentId::from_bytes([9u8; 32]), tx);

        let sink = Arc::new(SessionBroadcastSink::new(sessions.clone()));
        let state = InboxState::builder(
            Arc::new(NoopDenylist),
            Arc::new(StubWebFinger { pem: pub_pem }),
            sink,
        )
        .build();
        let router = server.with_inbox(state).router().0;

        let body = br#"{"type":"Create","object":{"type":"Note"}}"#;
        let url: url::Url = "https://relay.example/inbox".parse().unwrap();
        let req = signed_post(
            &priv_pem,
            body,
            "https://etchit.io/actors/josh#main-key",
            &url,
        );
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // The connected session received the broadcast PublicPost,
        // attributed to the canonical (fragment-stripped) actor URL.
        let frame = rx
            .try_recv()
            .expect("connected session received a broadcast");
        let ServerFrame::Deliver(d) = frame else {
            panic!("expected Deliver, got {frame:?}");
        };
        assert_eq!(d.envelope.kind, EnvelopeKind::PublicPost);
        let payload = PublicPostPayload::from_ciphertext(&d.envelope.ciphertext).unwrap();
        assert_eq!(payload.verified_actor_url, "https://etchit.io/actors/josh");
        assert_eq!(payload.activity_json, body);
    }

    #[tokio::test]
    async fn mounted_inbox_runs_gates_header_less_post_400() {
        let (_priv_pem, pub_pem) = keypair_pem();
        let state = InboxState::builder(
            Arc::new(NoopDenylist),
            Arc::new(StubWebFinger { pem: pub_pem }),
            Arc::new(RecordingSink::default()),
        )
        .build();
        let router = test_router(state);

        let req = Request::builder()
            .method("POST")
            .uri("/inbox")
            .body(Body::from("{}"))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        // Not 404 — the route is mounted and a header-less body trips
        // the missing-header gate inside `run_gates`.
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn inbox_route_absent_without_with_inbox() {
        let bind = "127.0.0.1:0".parse().unwrap();
        let router = Server::new(ServerConfig::defaults(bind, Region::Other("test".into())))
            .with_verifier(Arc::new(crate::signature::AcceptAllVerifier))
            .router()
            .0;
        let req = Request::builder()
            .method("POST")
            .uri("/inbox")
            .body(Body::from("{}"))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn with_inbox_auto_splices_metrics_into_v1_metrics() {
        use crate::inbox::{DropReason, InboxMetrics};
        let (_priv_pem, pub_pem) = keypair_pem();
        let metrics = Arc::new(InboxMetrics::new());
        metrics.record_drop(&DropReason::BodyTooLarge);
        let state = InboxState::builder(
            Arc::new(NoopDenylist),
            Arc::new(StubWebFinger { pem: pub_pem }),
            Arc::new(RecordingSink::default()),
        )
        .with_metrics(metrics)
        .build();
        let router = test_router(state);

        let req = Request::builder()
            .uri("/v1/metrics")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        let body_bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body = String::from_utf8(body_bytes.to_vec()).unwrap();
        // `with_inbox` (not `with_inbox_metrics`) auto-wires the splice
        // from the InboxState's own metrics Arc.
        assert!(
            body.contains("fedi_inbox_dropped_body_too_large_total 1"),
            "with_inbox must auto-splice the InboxState metrics:\n{body}"
        );
    }
}
