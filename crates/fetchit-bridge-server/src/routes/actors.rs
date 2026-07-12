//! Actor registration + document/collection serving.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use fetchit_fedi::actor::Actor;
use serde_json::Value;

use crate::server::BridgeState;
use crate::store::{ActorRecord, RegisterOutcome};

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

/// A handle must be a non-empty, URL-safe local-part: ASCII
/// alphanumerics plus `_` and `-`, capped at 64 chars. Excluding `.`
/// keeps it safe as a path segment (no `..` traversal) and as a
/// `WebFinger` `acct:` local-part.
fn is_valid_handle(handle: &str) -> bool {
    !handle.is_empty()
        && handle.len() <= 64
        && handle
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
}

/// `POST /actors` — register a fetch>it-native actor.
///
/// The body is the actor JSON-LD document. The handler parses it,
/// **verifies the ML-DSA attestation** (the unforgeable identity gate --
/// `from_json_ld` is structural only), **binds the actor id to this
/// bridge's own domain** (so a self-attested foreign id cannot hijack a
/// handle), then stores the canonical document keyed on the derived
/// agent id. `201` on first registration, `200` on idempotent update,
/// `409` if the handle is held by a different identity, `400`/`403` on
/// malformed / unattested / out-of-authority input.
pub async fn register(
    State(state): State<Arc<BridgeState>>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let actor = match Actor::from_json_ld(&body) {
        Ok(a) => a,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("malformed actor: {e}")).into_response()
        }
    };
    let agent_id = match actor.verify_attestation() {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::FORBIDDEN,
                format!("attestation rejected (not a fetch>it-native actor): {e}"),
            )
                .into_response()
        }
    };
    let handle = actor.preferred_username.clone();
    if !is_valid_handle(&handle) {
        return (StatusCode::BAD_REQUEST, "invalid handle").into_response();
    }
    // pre-public-exposure gate: anyone can mint a valid ML-DSA attestation,
    // so without this check an attacker could squat brand or operator handles
    // (e.g. "admin", "etchit") on this domain.
    if state
        .config
        .reserved_handles
        .contains(&handle.to_ascii_lowercase())
    {
        return (StatusCode::FORBIDDEN, "handle is reserved").into_response();
    }
    // cross-review P1: bind the registered identity to THIS bridge's
    // authority. The attestation binds the bundle but the signer picks
    // actor_url, so without this an attacker self-attests
    // id=https://evil.example/actors/<h> and acct:<h>@<domain> resolves
    // to their host. Require https://<our-domain>/actors/<handle>.
    let expected_path = format!("/actors/{handle}");
    // The bridge serves one canonical origin, so reject any explicit
    // non-default port. `url` normalises the default https port away, so
    // no-port and `:443` both yield `port() == None` (accepted); `:8443`
    // yields `Some(8443)` (rejected) -- closes the host_str()-excludes-port
    // gap (cross-review hardening).
    let id_ok = actor.id.scheme() == "https"
        && actor.id.port().is_none()
        && actor
            .id
            .host_str()
            .is_some_and(|h| h.eq_ignore_ascii_case(&state.config.domain))
        && actor.id.path() == expected_path.as_str();
    if !id_ok {
        return (
            StatusCode::FORBIDDEN,
            "actor id must be https://<domain>/actors/<handle> under this bridge",
        )
            .into_response();
    }
    let rec = ActorRecord {
        agent_id,
        handle,
        actor_url: actor.id.to_string(),
        doc_json: actor.to_json_ld().to_string(),
        registered_ms: now_ms(),
    };
    match state.store.register_actor(rec).await {
        Ok(RegisterOutcome::Created) => {
            state.metrics.inc_actors_registered();
            (StatusCode::CREATED, "registered").into_response()
        }
        Ok(RegisterOutcome::Updated) => {
            state.metrics.inc_actors_registered();
            (StatusCode::OK, "updated").into_response()
        }
        Ok(RegisterOutcome::HandleTaken) => {
            (StatusCode::CONFLICT, "handle already registered").into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "register_actor failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
        }
    }
}

/// `GET /actors/:handle` — the stored canonical actor JSON-LD document.
pub async fn get_actor(
    State(state): State<Arc<BridgeState>>,
    Path(handle): Path<String>,
) -> impl IntoResponse {
    state.metrics.inc_actor_doc();
    match state.store.actor_by_handle(&handle).await {
        Ok(Some(rec)) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/activity+json")],
            rec.doc_json,
        )
            .into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "no such actor").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "actor_by_handle failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
        }
    }
}

/// `GET /actors/:handle/followers` — an ordered collection (empty until
/// the Follow/fan-out milestone populates the `followers` table).
pub async fn followers(
    State(state): State<Arc<BridgeState>>,
    Path(handle): Path<String>,
) -> impl IntoResponse {
    empty_collection(&state, &handle, "followers").await
}

/// `GET /actors/:handle/outbox` — an ordered collection (empty for now).
pub async fn outbox(
    State(state): State<Arc<BridgeState>>,
    Path(handle): Path<String>,
) -> impl IntoResponse {
    empty_collection(&state, &handle, "outbox").await
}

async fn empty_collection(state: &Arc<BridgeState>, handle: &str, name: &str) -> Response {
    match state.store.actor_by_handle(handle).await {
        Ok(Some(rec)) => {
            let body = serde_json::json!({
                "@context": "https://www.w3.org/ns/activitystreams",
                "id": format!("{}/{name}", rec.actor_url),
                "type": "OrderedCollection",
                "totalItems": 0,
                "orderedItems": []
            });
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/activity+json")],
                body.to_string(),
            )
                .into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "no such actor").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "collection lookup failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
        }
    }
}
