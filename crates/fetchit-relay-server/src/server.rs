//! Top-level [`Server`] type — wires state, routes, and the background sweeper.

use crate::auth::AuthService;
use crate::capability::CapabilityResolver;
use crate::config::ServerConfig;
use crate::metrics::Metrics;
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
use tracing::info;

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
}

/// Builder + runner for one relay node.
pub struct Server {
    config: ServerConfig,
    verifier: Arc<dyn SignatureVerifier>,
}

impl Server {
    /// Construct a new server with the production verifier.
    #[must_use]
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            verifier: Arc::new(MlDsa65Verifier::new()),
        }
    }

    /// Inject a custom verifier (e.g. `AcceptAllVerifier` in tests).
    #[must_use]
    pub fn with_verifier(mut self, verifier: Arc<dyn SignatureVerifier>) -> Self {
        self.verifier = verifier;
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
            )),
            sessions: Arc::new(SessionRegistry::new()),
            verifier: self.verifier,
            capability_resolver: Arc::new(CapabilityResolver::new(self.config.issuer_keys.clone())),
            ratelimit: Arc::new(RateLimiter::new()),
            metrics,
            config: self.config,
        });
        let router = Router::new()
            .route("/v1/health", get(health))
            .route("/v1/metrics", get(metrics_handler))
            .route("/v1/auth/challenge", post(auth_challenge))
            .route("/v1/auth/verify", post(auth_verify))
            .route("/v1/ws", get(ws_handler))
            .with_state(state.clone());
        (router, state)
    }

    /// Bind, spawn the background sweeper, and serve forever.
    ///
    /// # Errors
    /// Returns any IO error from binding or serving.
    pub async fn run(self) -> Result<()> {
        let bind = self.config.bind;
        let region = self.config.region.clone();
        let (router, state) = self.router();
        let listener = TcpListener::bind(bind).await?;
        info!(%bind, %region, "fetchit-relay-server listening");
        spawn_sweeper(state);
        axum::serve(listener, router).await?;
        Ok(())
    }
}

fn spawn_sweeper(state: Arc<ServerState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let _ = state.transit.sweep_expired();
            let _ = state.auth.sweep_expired();
            state.ratelimit.sweep_idle(Duration::from_secs(3600));
            let buffered = i64::try_from(state.transit.len()).unwrap_or(i64::MAX);
            state.metrics.set_transit_buffer_envelopes(buffered);
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
        state.metrics.render_prometheus(),
    )
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
            Err((axum::http::StatusCode::UNAUTHORIZED, e.to_string()))
        }
    }
}
