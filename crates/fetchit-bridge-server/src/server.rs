//! Server assembly: shared state, router, and the run loop.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::StatusCode;
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;
use tracing::info;

use crate::config::BridgeConfig;
use crate::error::BridgeError;
use crate::metrics::BridgeMetrics;
use crate::ratelimit::{client_ip, RateLimiter};
use crate::routes;
use crate::store::Store;

/// Body cap for `POST /actors`. A real attested actor document is
/// ~10-20 KiB; this bounds an unauthenticated endpoint against
/// disk-fill / oversized-body denial of service (cross-review P3).
/// Scoped to the registration route only -- the read routes carry no body.
const MAX_REGISTER_BODY_BYTES: usize = 64 * 1024;

/// Bound on distinct IPs the registration limiter tracks, capping its memory
/// against a spray-many-source-IPs attack (cross-review pre-public).
const MAX_TRACKED_IPS: usize = 100_000;

/// Shared state handed to every handler.
pub struct BridgeState {
    /// Durable actor/follower store.
    pub store: Store,
    /// Static configuration.
    pub config: BridgeConfig,
    /// Process metrics.
    pub metrics: BridgeMetrics,
    /// Per-IP token-bucket limiter guarding `POST /actors`.
    pub rate_limiter: RateLimiter,
}

/// The bridge server.
pub struct Server {
    config: BridgeConfig,
    store: Store,
}

impl Server {
    /// Build a server from a config + an opened store.
    #[must_use]
    pub fn new(config: BridgeConfig, store: Store) -> Self {
        Self { config, store }
    }

    /// Assemble the axum router and shared state.
    pub fn router(self) -> (Router, Arc<BridgeState>) {
        let metrics = BridgeMetrics::new(self.config.server_version.clone());
        let rate_limiter = RateLimiter::new(
            self.config.register_burst,
            f64::from(self.config.register_per_min) / 60.0,
            MAX_TRACKED_IPS,
        );
        let state = Arc::new(BridgeState {
            store: self.store,
            config: self.config,
            metrics,
            rate_limiter,
        });
        let router = Router::new()
            .route("/health", get(routes::health::health))
            .route("/metrics", get(routes::health::metrics))
            .route(
                "/actors",
                post(routes::actors::register)
                    .layer(DefaultBodyLimit::max(MAX_REGISTER_BODY_BYTES))
                    .layer(from_fn_with_state(state.clone(), rate_limit_register)),
            )
            .route("/actors/:handle", get(routes::actors::get_actor))
            .route("/actors/:handle/followers", get(routes::actors::followers))
            .route(
                "/actors/:handle/followers/list",
                get(routes::follow::followers_list),
            )
            .route(
                "/actors/:handle/following",
                post(routes::follow::record_follow).get(routes::follow::following_list),
            )
            .route("/actors/:handle/unfollow", post(routes::follow::unfollow))
            .route(
                "/actors/:handle/followers/confirm",
                post(routes::follow::confirm_follower),
            )
            .route(
                "/actors/:handle/follow-requests",
                get(routes::follow::follow_requests),
            )
            .route("/actors/:handle/outbox", get(routes::actors::outbox))
            .route("/actors/:handle/inbox", post(routes::inbox::post_inbox))
            .route("/actors/:handle/messages", get(routes::inbox::get_messages))
            .route("/.well-known/webfinger", get(routes::webfinger::webfinger))
            .with_state(state.clone());
        (router, state)
    }

    /// Bind the listener and serve until shutdown.
    ///
    /// # Errors
    /// Returns [`BridgeError::Config`] if the bind fails or the server
    /// exits abnormally.
    pub async fn run(self) -> Result<(), BridgeError> {
        let bind = self.config.bind;
        let burst = self.config.register_burst;
        let per_min = self.config.register_per_min;
        let hops = self.config.trusted_proxy_hops;
        let (router, _state) = self.router();
        let listener = TcpListener::bind(bind)
            .await
            .map_err(|e| BridgeError::Config(format!("bind {bind}: {e}")))?;
        info!(%bind, "fetchit-bridge-server listening");
        if burst == 0 {
            tracing::warn!(
                "registration rate limiter is DISABLED \
                 (FETCHIT_BRIDGE_REGISTER_BURST=0); POST /actors is unthrottled"
            );
        } else {
            info!(burst, per_min, hops, "registration rate limiter active");
        }
        // ConnectInfo is wired so the rate-limit middleware can read the
        // socket peer address (its secure-default client-IP source).
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .map_err(|e| BridgeError::Config(format!("serve: {e}")))?;
        Ok(())
    }
}

/// Middleware gating `POST /actors` with the per-IP token-bucket limiter.
///
/// It runs before the body is buffered, so a limited client is rejected
/// without allocating its (capped) request body, and returns
/// `429 Too Many Requests`. The client IP is resolved by
/// [`client_ip`](crate::ratelimit::client_ip): the socket peer by default,
/// or an `X-Forwarded-For` entry when the operator has configured trusted
/// proxy hops.
async fn rate_limit_register(
    State(state): State<Arc<BridgeState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let ip = client_ip(
        peer.ip(),
        request.headers(),
        state.config.trusted_proxy_hops,
    );
    if state.rate_limiter.check(ip, Instant::now()) {
        next.run(request).await
    } else {
        (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response()
    }
}
