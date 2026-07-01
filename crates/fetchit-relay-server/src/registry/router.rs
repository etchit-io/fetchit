//! Axum router + handlers for the registry + serving endpoints. Thin
//! handlers delegate to `?`-ergonomic inner fns the unit tests drive
//! without the axum layer (mirrors [`crate::inbox::router`]).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, RawQuery, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Router;
use serde_json::json;

use crate::forwarding::now_ms;
use crate::inbox::InboxRateLimit;
use crate::registry::actor_doc::actor_document;
use crate::registry::verify::validate_registry_handle;
use crate::registry::webfinger::{parse_acct_resource, webfinger_jrd};
use crate::registry::{
    verify_registration, ActorRegistryStore, RegistryConfig, RegistryRejection, RegistryStoreError,
};
use fetchit_fedi::registry::RegisterActorRequest;

/// Shared registry state on the axum router.
#[derive(Clone)]
pub struct RegistryState {
    /// Verified-registration store (FCFS + continuity).
    pub store: Arc<dyn ActorRegistryStore>,
    /// Bridge domain + verification config.
    pub config: RegistryConfig,
    /// Per-source token bucket (reused from the inbox).
    pub rate_limit: Arc<InboxRateLimit>,
}

/// The HTTP outcome of an endpoint: status + body string. Concrete so
/// inner fns are unit-testable without the axum layer.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    status: u16,
    body: String,
}

/// Map a verification rejection to its 422 outcome.
fn rejection_outcome(r: &RegistryRejection) -> Outcome {
    Outcome {
        status: 422,
        body: r.to_string(),
    }
}

/// Map a store error to its outcome (404 / 409 / 500).
fn store_outcome(e: &RegistryStoreError) -> Outcome {
    match e {
        RegistryStoreError::UnknownHandle => Outcome {
            status: 404,
            body: e.to_string(),
        },
        RegistryStoreError::HandleTaken
        | RegistryStoreError::AgentMismatch
        | RegistryStoreError::StaleEpoch => Outcome {
            status: 409,
            body: e.to_string(),
        },
        // Never leak SQL / IO internals to the caller; the detail is logged.
        RegistryStoreError::Storage(_) => Outcome {
            status: 500,
            body: "internal error".into(),
        },
    }
}

/// POST /v1/actors core: parse -> verify -> register. 201 on success.
fn register_inner(state: &RegistryState, body: &[u8], now: u64) -> Outcome {
    let req: RegisterActorRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return rejection_outcome(&RegistryRejection::Body(e.to_string())),
    };
    // Validate the handle first (422), then the reserved-handle gate (403,
    // register-only: an already-held handle is updated, not re-acquired).
    // The gate precedes verify so a squatter cannot burn crypto on a
    // reserved handle.
    if let Err(e) = validate_registry_handle(&req.handle) {
        return rejection_outcome(&e);
    }
    if state.config.is_reserved(&req.handle) {
        return Outcome {
            status: 403,
            body: "handle is reserved".into(),
        };
    }
    let record = match verify_registration(&state.config, &req, now) {
        Ok(r) => r,
        Err(e) => return rejection_outcome(&e),
    };
    let actor_url = record.actor_url.clone();
    match state.store.register(record) {
        Ok(()) => Outcome {
            status: 201,
            body: json!({ "actor_url": actor_url }).to_string(),
        },
        Err(e) => store_outcome(&e),
    }
}

/// PUT /v1/actors/<handle> core: parse -> path/body handle agreement ->
/// verify -> store.update.
fn update_inner(state: &RegistryState, path_handle: &str, body: &[u8], now: u64) -> Outcome {
    let req: RegisterActorRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return rejection_outcome(&RegistryRejection::Body(e.to_string())),
    };
    if req.handle != path_handle {
        return rejection_outcome(&RegistryRejection::HandleMismatch {
            path: path_handle.to_string(),
            body: req.handle.clone(),
        });
    }
    let record = match verify_registration(&state.config, &req, now) {
        Ok(r) => r,
        Err(e) => return rejection_outcome(&e),
    };
    let actor_url = record.actor_url.clone();
    match state.store.update(record) {
        Ok(()) => Outcome {
            status: 200,
            body: json!({ "actor_url": actor_url }).to_string(),
        },
        Err(e) => store_outcome(&e),
    }
}

/// GET /.well-known/webfinger?resource=acct:<h>@<domain>
fn webfinger_inner(state: &RegistryState, raw_query: Option<&str>) -> Outcome {
    let resource = raw_query.and_then(|q| {
        url::form_urlencoded::parse(q.as_bytes())
            .find(|(k, _)| k == "resource")
            .map(|(_, v)| v.into_owned())
    });
    let Some(resource) = resource else {
        return Outcome {
            status: 400,
            body: "missing resource".into(),
        };
    };
    let Some((handle, domain)) = parse_acct_resource(&resource) else {
        return Outcome {
            status: 400,
            body: "malformed resource".into(),
        };
    };
    if domain != state.config.domain {
        return Outcome {
            status: 404,
            body: "unknown".into(),
        };
    }
    match state.store.get(&handle) {
        Some(record) => Outcome {
            status: 200,
            body: webfinger_jrd(&record, &state.config.domain).to_string(),
        },
        None => Outcome {
            status: 404,
            body: "unknown".into(),
        },
    }
}

/// GET /actors/<handle>
fn actor_doc_inner(state: &RegistryState, handle: &str) -> Outcome {
    match state.store.get(handle) {
        Some(record) => Outcome {
            status: 200,
            body: actor_document(&record).to_string(),
        },
        None => Outcome {
            status: 404,
            body: "unknown".into(),
        },
    }
}

/// Extract the rate-limit source key. SECURITY (Alice's flag-2 catch):
/// leftmost `X-Forwarded-For` is CLIENT-SPOOFABLE when a proxy appends
/// rather than overwrites, so we do NOT key on it. The bridge's sole
/// ingress is Cloudflare + the CF Worker; the Worker forwards the
/// authoritative client IP (`CF-Connecting-IP`, Cloudflare-set and
/// unforgeable) in `trusted_header`. We key on that header only,
/// falling back to the connection peer for non-CF / test paths. Origin
/// reachability MUST be restricted to the Worker so the trusted header
/// cannot be set by a direct caller.
fn source_key(headers: &HeaderMap, trusted_header: &str, peer: Option<IpAddr>) -> String {
    headers
        .get(trusted_header)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| peer.map(|p| p.to_string()))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Build a register/update response: `application/json` body on success.
fn registry_response(out: Outcome) -> Response {
    let status = StatusCode::from_u16(out.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if matches!(out.status, 200 | 201) {
        (
            status,
            [(header::CONTENT_TYPE, "application/json")],
            out.body,
        )
            .into_response()
    } else {
        (status, out.body).into_response()
    }
}

/// Build a serving (GET) response with the right JSON-LD content type
/// on a 200, plain text otherwise.
fn serving_response(out: Outcome, content_type: &'static str) -> Response {
    let status = StatusCode::from_u16(out.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if out.status == 200 {
        (status, [(header::CONTENT_TYPE, content_type)], out.body).into_response()
    } else {
        (status, out.body).into_response()
    }
}

async fn handle_register(
    State(state): State<RegistryState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    body: Bytes,
) -> Response {
    let key = source_key(
        &headers,
        &state.config.trusted_client_ip_header,
        peer.map(|c| c.0.ip()),
    );
    if !state.rate_limit.allow(&key) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    registry_response(register_inner(&state, &body, now_ms()))
}

async fn handle_update(
    State(state): State<RegistryState>,
    Path(handle): Path<String>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    body: Bytes,
) -> Response {
    let key = source_key(
        &headers,
        &state.config.trusted_client_ip_header,
        peer.map(|c| c.0.ip()),
    );
    if !state.rate_limit.allow(&key) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    registry_response(update_inner(&state, &handle, &body, now_ms()))
}

async fn handle_webfinger(State(state): State<RegistryState>, RawQuery(q): RawQuery) -> Response {
    serving_response(
        webfinger_inner(&state, q.as_deref()),
        "application/jrd+json",
    )
}

async fn handle_actor_doc(
    State(state): State<RegistryState>,
    Path(handle): Path<String>,
) -> Response {
    serving_response(
        actor_doc_inner(&state, &handle),
        "application/activity+json",
    )
}

/// Tight request-body cap for the registry write routes (Alice F4). A
/// registration is ~5 KB (ML-DSA-65 sig + RSA SPKI, base64); 64 KB is
/// generous but far below axum's 2 MB default for an unauthenticated
/// endpoint. Oversized bodies are rejected with 413 before the handler.
const REGISTRY_MAX_BODY: usize = 64 * 1024;

/// Build the registry + serving router (axum 0.7 `:handle` path params).
pub fn registry_router(state: RegistryState) -> Router {
    Router::new()
        .route("/v1/actors", post(handle_register))
        .route("/v1/actors/:handle", put(handle_update))
        .route("/.well-known/webfinger", get(handle_webfinger))
        .route("/actors/:handle", get(handle_actor_doc))
        .layer(DefaultBodyLimit::max(REGISTRY_MAX_BODY))
        .with_state(state)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::registry::InMemoryActorStore;
    use fetchit_fedi::attestation::ActorAttestationV2;

    const VALID: &str = include_str!(
        "../../../fetchit-fedi/tests/fixtures/registry-v1/register-request-valid.json"
    );

    fn state() -> RegistryState {
        RegistryState {
            store: Arc::new(InMemoryActorStore::new()),
            config: RegistryConfig::new("etchit.io"),
            rate_limit: Arc::new(InboxRateLimit::new(1000)),
        }
    }

    fn valid_request() -> RegisterActorRequest {
        serde_json::from_str(VALID).unwrap()
    }

    // ---- Task 9: POST /v1/actors ----

    #[test]
    fn register_valid_returns_201_with_actor_url() {
        let st = state();
        let out = register_inner(&st, VALID.as_bytes(), 1);
        assert_eq!(out.status, 201);
        assert_eq!(out.body, r#"{"actor_url":"https://etchit.io/actors/josh"}"#);
    }

    #[test]
    fn register_duplicate_returns_409() {
        let st = state();
        assert_eq!(register_inner(&st, VALID.as_bytes(), 1).status, 201);
        assert_eq!(register_inner(&st, VALID.as_bytes(), 2).status, 409);
    }

    #[test]
    fn register_uppercase_handle_returns_422() {
        let st = state();
        let mut v: serde_json::Value = serde_json::from_str(VALID).unwrap();
        v["handle"] = json!("Josh");
        assert_eq!(register_inner(&st, v.to_string().as_bytes(), 1).status, 422);
    }

    #[test]
    fn register_malformed_body_returns_422() {
        let st = state();
        assert_eq!(register_inner(&st, b"not json", 1).status, 422);
    }

    // ---- Reserved-handle gate (403) ----

    #[test]
    fn register_reserved_word_returns_403_before_verify() {
        let mut config = RegistryConfig::new("etchit.io");
        config.reserved_handles = ["josh".to_string()].into_iter().collect();
        let st = RegistryState {
            store: Arc::new(InMemoryActorStore::new()),
            config,
            rate_limit: Arc::new(InboxRateLimit::new(1000)),
        };
        let out = register_inner(&st, VALID.as_bytes(), 1);
        assert_eq!(out.status, 403);
        assert_eq!(out.body, "handle is reserved");
    }

    #[test]
    fn register_short_handle_reserved_by_min_len_returns_403() {
        let mut config = RegistryConfig::new("etchit.io");
        config.reserved_min_len = 4; // "josh" is 4 chars
        let st = RegistryState {
            store: Arc::new(InMemoryActorStore::new()),
            config,
            rate_limit: Arc::new(InboxRateLimit::new(1000)),
        };
        assert_eq!(register_inner(&st, VALID.as_bytes(), 1).status, 403);
    }

    #[test]
    fn register_invalid_handle_stays_422_not_403() {
        // Uppercase is invalid -> 422 from handle-validate, BEFORE the
        // reserved gate (which would otherwise 403 a <=8 char handle).
        let mut config = RegistryConfig::new("etchit.io");
        config.reserved_min_len = 8;
        let st = RegistryState {
            store: Arc::new(InMemoryActorStore::new()),
            config,
            rate_limit: Arc::new(InboxRateLimit::new(1000)),
        };
        let mut v: serde_json::Value = serde_json::from_str(VALID).unwrap();
        v["handle"] = json!("Josh");
        assert_eq!(register_inner(&st, v.to_string().as_bytes(), 1).status, 422);
    }

    // ---- Task 10: PUT /v1/actors/<handle> ----

    #[test]
    fn update_unknown_handle_returns_404() {
        let st = state();
        // Valid signature, but the handle was never registered.
        assert_eq!(update_inner(&st, "josh", VALID.as_bytes(), 1).status, 404);
    }

    #[test]
    fn update_path_body_handle_mismatch_returns_422() {
        let st = state();
        let mut v: serde_json::Value = serde_json::from_str(VALID).unwrap();
        v["handle"] = json!("alice");
        assert_eq!(
            update_inner(&st, "josh", v.to_string().as_bytes(), 1).status,
            422
        );
    }

    /// PUT 200 path: one keypair, two epochs (re-sign helper, no shared
    /// committed fixture -- confirmed with Alice). Register epoch 1000,
    /// update epoch 2000 (same agent, newer) -> 200; re-PUT epoch 1000
    /// (stale) -> 409.
    #[test]
    fn update_same_agent_newer_epoch_returns_200_then_stale_409() {
        use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};
        let st = state();
        let spki = valid_request().rsa_spki_der;
        let actor_url: url::Url = "https://etchit.io/actors/josh".parse().unwrap();
        let profile = "a".repeat(64);
        let relay = "https://relay.example:8088/";
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let pk_bytes = pk.to_bytes();
        let derived = hex::encode(fetchit_relay_proto::derive_agent_id(&pk_bytes));
        let build = |epoch: u64| -> Vec<u8> {
            let input = fetchit_fedi::attestation::signing_input_v2(
                "josh", &actor_url, &derived, &spki, &profile, relay, epoch,
            )
            .unwrap();
            let sig = dsa.sign(&sk, &input).unwrap().to_bytes();
            let req = RegisterActorRequest {
                handle: "josh".into(),
                rsa_spki_der: spki.clone(),
                attestation_v2: ActorAttestationV2 {
                    version: 2,
                    profile_addr: profile.clone(),
                    relay_hint: relay.into(),
                    hint_epoch_ms: epoch,
                    ml_dsa_pubkey: pk_bytes.clone(),
                    signature: sig,
                },
            };
            serde_json::to_vec(&req).unwrap()
        };
        assert_eq!(register_inner(&st, &build(1_000), 1).status, 201);
        let out = update_inner(&st, "josh", &build(2_000), 2);
        assert_eq!(out.status, 200);
        assert_eq!(out.body, r#"{"actor_url":"https://etchit.io/actors/josh"}"#);
        // Stale epoch -> 409.
        assert_eq!(update_inner(&st, "josh", &build(1_000), 3).status, 409);
    }

    // ---- Task 11: WebFinger + actor-doc GET + rate limit ----

    #[test]
    fn webfinger_known_handle_returns_jrd() {
        let st = state();
        register_inner(&st, VALID.as_bytes(), 1);
        let out = webfinger_inner(&st, Some("resource=acct:josh@etchit.io"));
        assert_eq!(out.status, 200);
        assert!(out
            .body
            .contains(r#""href":"https://etchit.io/actors/josh""#));
    }

    #[test]
    fn webfinger_unknown_foreign_and_malformed() {
        let st = state();
        assert_eq!(
            webfinger_inner(&st, Some("resource=acct:ghost@etchit.io")).status,
            404
        );
        assert_eq!(
            webfinger_inner(&st, Some("resource=acct:josh@evil.example")).status,
            404
        );
        assert_eq!(webfinger_inner(&st, Some("resource=not-acct")).status, 400);
        assert_eq!(webfinger_inner(&st, None).status, 400);
    }

    #[test]
    fn actor_doc_known_200_unknown_404() {
        let st = state();
        register_inner(&st, VALID.as_bytes(), 1);
        assert_eq!(actor_doc_inner(&st, "josh").status, 200);
        assert_eq!(actor_doc_inner(&st, "ghost").status, 404);
    }

    #[test]
    fn rate_limit_drains_to_429_per_source() {
        let rl = InboxRateLimit::new(1);
        assert!(rl.allow("1.2.3.4"));
        assert!(!rl.allow("1.2.3.4"));
        // A different source still has budget.
        assert!(rl.allow("5.6.7.8"));
    }

    fn unknown_source_key() -> String {
        source_key(&HeaderMap::new(), "x-real-ip", None)
    }

    #[test]
    fn source_key_falls_back_to_unknown_without_header_or_peer() {
        assert_eq!(unknown_source_key(), "unknown");
    }

    #[test]
    fn source_key_prefers_trusted_header_over_peer() {
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", "203.0.113.7".parse().unwrap());
        let peer: Option<IpAddr> = Some("10.0.0.1".parse().unwrap());
        assert_eq!(source_key(&h, "x-real-ip", peer), "203.0.113.7");
    }

    // ---- Task 12: full-router integration (axum oneshot) ----

    #[tokio::test]
    async fn full_router_register_then_webfinger_then_actor_doc() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = registry_router(state());

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/actors")
                    .header("content-type", "application/json")
                    .body(Body::from(VALID))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/.well-known/webfinger?resource=acct:josh@etchit.io")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/actors/josh")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()["content-type"].to_str().unwrap(),
            "application/activity+json"
        );
    }

    #[tokio::test]
    async fn handler_rate_limit_returns_429() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let st = RegistryState {
            store: Arc::new(InMemoryActorStore::new()),
            config: RegistryConfig::new("etchit.io"),
            rate_limit: Arc::new(InboxRateLimit::new(1)),
        };
        let app = registry_router(st);
        // Both requests share the "unknown" source (no header, no peer):
        // the first burns the single token, the second is limited.
        let r1 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/actors")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(r1.status(), StatusCode::TOO_MANY_REQUESTS);
        let r2 = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/actors")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r2.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn tombstoned_row_is_ghost_free_across_webfinger_actordoc_and_put() {
        // Alice's note: PIN the ghost-free claim, don't imply it. A
        // tombstoned handle 404s on webfinger + actor-doc + PUT via the
        // store's `tombstoned_at IS NULL` filter. Uses the real SQLite
        // store (the in-memory store has no tombstone path).
        use crate::registry::SqliteActorStore;
        let store = Arc::new(SqliteActorStore::open(":memory:").unwrap());
        let config = RegistryConfig::new("etchit.io");
        let req: RegisterActorRequest = serde_json::from_str(VALID).unwrap();
        store
            .register(verify_registration(&config, &req, 1).unwrap())
            .unwrap();
        store.tombstone("josh", 999).unwrap();
        let st = RegistryState {
            store: store.clone(),
            config,
            rate_limit: Arc::new(InboxRateLimit::new(1000)),
        };
        assert_eq!(
            webfinger_inner(&st, Some("resource=acct:josh@etchit.io")).status,
            404,
            "webfinger must not resurrect a tombstoned actor"
        );
        assert_eq!(
            actor_doc_inner(&st, "josh").status,
            404,
            "actor-doc must not resurrect a tombstoned actor"
        );
        assert_eq!(
            update_inner(&st, "josh", VALID.as_bytes(), 2).status,
            404,
            "PUT on a tombstoned handle is unknown, not an update"
        );
    }

    #[tokio::test]
    async fn oversize_body_is_rejected_with_413() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;
        let app = registry_router(state());
        let big = vec![b'x'; 70 * 1024]; // over the 64 KB cap
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/actors")
                    .body(Body::from(big))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_serve_header_less_request_is_peer_keyed_not_unknown() {
        use std::net::SocketAddr;
        use tokio::net::TcpListener;
        // F1 DISCRIMINATING guard (Alice's note). Over loopback both
        // requests share 127.0.0.1, so a plain "two header-less POSTs ->
        // 2nd is 429" assertion passes whether the source key is the live
        // peer IP (fixed) or the constant "unknown" (reverted) -- it does
        // not actually guard the connect-info line. So instead: req1 with
        // NO header (keyed on the live peer) + req2 with x-real-ip set to
        // 127.0.0.1 (keyed on the trusted header). With the fix the peer
        // key IS 127.0.0.1, so both land in the SAME 1-token bucket and
        // req2 is 429. If the connect-info line were reverted, req1 would
        // key on "unknown" and req2 on "127.0.0.1" -- different buckets,
        // and req2 would pass. So this 429 proves connect-info is wired.
        let st = RegistryState {
            store: Arc::new(InMemoryActorStore::new()),
            config: RegistryConfig::new("etchit.io"),
            rate_limit: Arc::new(InboxRateLimit::new(1)),
        };
        let app = registry_router(st);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/v1/actors");
        // req1: no x-real-ip -> source key falls back to the live peer
        // (127.0.0.1 under the fix; "unknown" if connect-info reverted).
        let r1 = client.post(&url).body("{}").send().await.unwrap();
        assert_ne!(r1.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
        // req2: x-real-ip:127.0.0.1 -> keyed on the header. Shares req1's
        // bucket ONLY because the fix made req1's peer key 127.0.0.1 too.
        let r2 = client
            .post(&url)
            .header("x-real-ip", "127.0.0.1")
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(r2.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn registry_router_round_trips_over_the_sqlite_store() {
        // F7 close-out (Alice's note): every other router test drives the
        // in-memory store, and the F6 tombstone test calls the _inner fns
        // directly -- so the router<->SqliteActorStore seam (the exact
        // blind spot that hid F1) had zero coverage. Drive a real register
        // + serve round trip through the axum router backed by a :memory:
        // SqliteActorStore: the 201 writes through the router into SQLite,
        // and the GETs read it back through the router.
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;
        let st = RegistryState {
            store: Arc::new(crate::registry::SqliteActorStore::open(":memory:").unwrap()),
            config: RegistryConfig::new("etchit.io"),
            rate_limit: Arc::new(InboxRateLimit::new(1000)),
        };
        let app = registry_router(st);
        let reg = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/actors")
                    .body(Body::from(VALID))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reg.status(), StatusCode::CREATED);
        // Actor doc served back out of SQLite, through the router.
        let doc = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/actors/josh")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(doc.status(), StatusCode::OK);
        // WebFinger resolves the same handle over the SQLite store.
        let wf = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/.well-known/webfinger?resource=acct:josh@etchit.io")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wf.status(), StatusCode::OK);
    }
}
