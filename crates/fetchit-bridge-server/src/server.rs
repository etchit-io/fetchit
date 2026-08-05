//! Server assembly: shared state, router, and the run loop.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::{Method, StatusCode};
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

/// Inbox per-IP burst. Generous — a big instance's shared outbox
/// delivers from few IPs in clusters — but bounds a single-source
/// flood of the unauthenticated federation endpoint (cross-review
/// 2026-08-03 finding 1).
const INBOX_BURST: u32 = 60;
/// Inbox per-IP sustained refill, tokens per second (120/min).
const INBOX_REFILL_PER_SEC: f64 = 2.0;

/// Body cap for `POST /actors/:handle/avatar`, mirroring the cap the
/// avatar FETCH path enforces on remote images. Oversized uploads are
/// rejected as `413` by the layer, before the handler allocates them.
const MAX_AVATAR_BODY_BYTES: usize = fetchit_fedi::avatar::MAX_AVATAR_BYTES;

/// Avatar-write per-IP burst.
///
/// Sized for the deployment, not for one person: the limiter keys on the
/// client IP as [`client_ip`] resolves it, which is the socket peer
/// unless the operator has configured `trusted_proxy_hops`. Behind the
/// edge worker that peer is the EDGE, so this bucket is shared by
/// everyone -- the same reasoning [`INBOX_BURST`] carries. A per-user
/// value here would lock out the second person to set a picture in the
/// same minute. Worst case it still bounds writes to
/// 30 x [`MAX_AVATAR_BODY_BYTES`] per minute.
const AVATAR_WRITE_BURST: u32 = 30;
/// Avatar-write per-IP sustained refill, tokens per second (30/min).
const AVATAR_WRITE_REFILL_PER_SEC: f64 = 0.5;

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
    /// Per-IP token-bucket limiter guarding `POST /actors/:handle/inbox`.
    pub rate_limiter_inbox: RateLimiter,
    /// Per-IP token-bucket limiter guarding the avatar WRITE verbs. The
    /// public avatar GET is deliberately outside it — whole instances
    /// fetch avatars from one egress IP.
    pub rate_limiter_avatar: RateLimiter,
    /// Signed community denylist consulted by the inbound federation
    /// gate. `None` disables the gate (fail-open); see
    /// [`crate::denylist`].
    pub denylist: Option<Arc<dyn fetchit_trust_types::DenylistQuery>>,
}

/// The bridge server.
pub struct Server {
    config: BridgeConfig,
    store: Store,
    denylist: Option<Arc<dyn fetchit_trust_types::DenylistQuery>>,
}

impl Server {
    /// Build a server from a config + an opened store. The inbound
    /// denylist gate is off until [`Self::with_denylist`] wires it.
    #[must_use]
    pub fn new(config: BridgeConfig, store: Store) -> Self {
        Self {
            config,
            store,
            denylist: None,
        }
    }

    /// Wire the community denylist the inbound federation gate consults.
    ///
    /// Separate from [`Self::new`] because building the consumer spawns
    /// a background poll loop (so it needs a Tokio runtime), while
    /// `new` + [`Self::router`] are sync and used by every hermetic
    /// test. Production assembles it in `main` via
    /// [`crate::denylist::install`].
    #[must_use]
    pub fn with_denylist(mut self, denylist: Arc<dyn fetchit_trust_types::DenylistQuery>) -> Self {
        self.denylist = Some(denylist);
        self
    }

    /// Assemble the axum router and shared state.
    pub fn router(self) -> (Router, Arc<BridgeState>) {
        let metrics = BridgeMetrics::new(self.config.server_version.clone());
        let rate_limiter = RateLimiter::new(
            self.config.register_burst,
            f64::from(self.config.register_per_min) / 60.0,
            MAX_TRACKED_IPS,
        );
        let rate_limiter_inbox =
            RateLimiter::new(INBOX_BURST, INBOX_REFILL_PER_SEC, MAX_TRACKED_IPS);
        let rate_limiter_avatar = RateLimiter::new(
            AVATAR_WRITE_BURST,
            AVATAR_WRITE_REFILL_PER_SEC,
            MAX_TRACKED_IPS,
        );
        let state = Arc::new(BridgeState {
            store: self.store,
            config: self.config,
            metrics,
            rate_limiter,
            rate_limiter_inbox,
            rate_limiter_avatar,
            denylist: self.denylist,
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
            .route(
                "/actors/:handle/avatar",
                get(routes::avatar::get_avatar)
                    .post(routes::avatar::post_avatar)
                    .delete(routes::avatar::delete_avatar)
                    .layer(DefaultBodyLimit::max(MAX_AVATAR_BODY_BYTES))
                    .layer(from_fn_with_state(state.clone(), rate_limit_avatar_write)),
            )
            .route("/actors/:handle/outbox", get(routes::actors::outbox))
            .route(
                "/actors/:handle/inbox",
                post(routes::inbox::post_inbox)
                    .layer(from_fn_with_state(state.clone(), rate_limit_inbox)),
            )
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

/// Per-IP limiter for the avatar WRITE verbs only.
///
/// `GET` is exempt on purpose: it is the public `icon` URL, and a large
/// instance renders many timelines from behind one egress IP, so
/// bucketing reads would blank avatars for whole servers. Only the
/// authenticated, state-changing verbs are throttled.
async fn rate_limit_avatar_write(
    State(state): State<Arc<BridgeState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    if matches!(*request.method(), Method::GET | Method::HEAD) {
        return next.run(request).await;
    }
    let ip = client_ip(
        peer.ip(),
        request.headers(),
        state.config.trusted_proxy_hops,
    );
    if state.rate_limiter_avatar.check(ip, Instant::now()) {
        next.run(request).await
    } else {
        (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response()
    }
}

/// Per-IP limiter for the unauthenticated federation inbox. 429 is a
/// retryable signal to well-behaved remote queues, so legitimate bursts
/// beyond the bucket only delay, never lose, deliveries.
async fn rate_limit_inbox(
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
    if state.rate_limiter_inbox.check(ip, Instant::now()) {
        next.run(request).await
    } else {
        (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response()
    }
}
