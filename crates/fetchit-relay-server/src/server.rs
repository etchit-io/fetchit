//! Top-level [`Server`] type — wires state, routes, and the background sweeper.

use crate::auth::AuthService;
use crate::capability::CapabilityResolver;
use crate::config::ServerConfig;
#[cfg(feature = "fediverse-inbox")]
use crate::inbox::InboxMetrics;
use crate::metrics::Metrics;
use crate::profile::{delete_profile, get_profile, post_profile, ProfileIndex};
use crate::ratelimit::RateLimiter;
use crate::session::SessionRegistry;
use crate::signature::{MlDsa65Verifier, SignatureVerifier};
use crate::transit::TransitBuffer;
use crate::ws::ws_handler;
use anyhow::Result;
use axum::extract::State;
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
    #[cfg(feature = "fediverse-inbox")]
    inbox_metrics: Option<Arc<InboxMetrics>>,
}

impl Server {
    /// Construct a new server with the production verifier.
    #[must_use]
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            verifier: Arc::new(MlDsa65Verifier::new()),
            #[cfg(feature = "fediverse-inbox")]
            inbox_metrics: None,
        }
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

    /// Assemble the axum router and shared state, consuming `self`.
    pub fn router(self) -> (Router, Arc<ServerState>) {
        let metrics = Arc::new(Metrics::new(
            self.config.region.clone(),
            self.config.server_version.clone(),
        ));
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
            sessions: Arc::new(SessionRegistry::new()),
            verifier: self.verifier,
            capability_resolver: Arc::new(CapabilityResolver::new(self.config.issuer_keys.clone())),
            ratelimit: Arc::new(RateLimiter::new()),
            metrics,
            profiles: ProfileIndex::new(),
            config: self.config,
            #[cfg(feature = "fediverse-inbox")]
            inbox_metrics: self.inbox_metrics,
        });
        let router = Router::new()
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
            .with_state(state.clone());
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
        axum::serve(listener, router).await?;
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
