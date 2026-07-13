//! Client-authed follow-state endpoints (M7 P1).
//!
//! These endpoints RECORD state; they never sign or deliver. The device
//! signs + delivers every activity itself (`FediverseTransport`), then
//! tells the bridge what happened. Every handler here runs
//! `bridge-auth-v1` ([`crate::auth`]) against the ML-DSA key attested in
//! the STORED actor document, so only the registered owner of a handle
//! can mutate or read its follow graph.
//!
//! * `POST   /actors/:handle/following`        — record an outbound follow (pending)
//! * `POST   /actors/:handle/unfollow`         — drop a follow (client already sent `Undo`)
//! * `GET    /actors/:handle/following`        — owner-only list (privacy: items are
//!   not public in v1; the public AP collection serves counts only)
//! * `POST   /actors/:handle/followers/confirm` — record a follower after the
//!   client delivered its signed `Accept`
//!
//! Inbound `Follow`/`Accept`/`Undo` from remote servers land on the
//! bridge INBOX route (HTTP-signature gates), not here.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use fetchit_fedi::actor::Actor;
use serde::Deserialize;
use serde_json::json;

use crate::auth::{parse_headers, verify_request, AuthError};
use crate::server::BridgeState;
use crate::store::ActorRecord;
use crate::store_follow::FollowOutcome;

/// Milliseconds since the unix epoch (single clock source for this
/// module; tolerates pre-epoch clocks by clamping to 0).
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Run `bridge-auth-v1` for `handle` over this exact request. Returns
/// the actor record on success so handlers don't re-query.
///
/// 401 for header/shape problems, 403 for a failed binding, 404 for an
/// unknown handle — the same order a caller probes.
async fn auth_actor(
    state: &BridgeState,
    handle: &str,
    headers: &HeaderMap,
    method: &Method,
    path: &str,
    body: &[u8],
) -> Result<ActorRecord, Response> {
    let hdrs = parse_headers(headers)
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("auth: {e}")).into_response())?;
    let rec = match state.store.actor_by_handle(handle).await {
        Ok(Some(r)) => r,
        Ok(None) => return Err((StatusCode::NOT_FOUND, "unknown handle").into_response()),
        Err(e) => {
            tracing::warn!(error = %e, "actor_by_handle failed");
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response());
        }
    };
    let doc: serde_json::Value =
        serde_json::from_str(&rec.doc_json).map_err(|e| unusable(&format!("stored doc: {e}")))?;
    let actor = Actor::from_json_ld(&doc).map_err(|e| unusable(&format!("stored actor: {e}")))?;
    // Prefer the v2 attestation key; fall back to v1, which is a
    // required field (registration verified the binding).
    let pubkey = actor.ml_dsa_attestation_v2.as_ref().map_or_else(
        || actor.ml_dsa_attestation.ml_dsa_pubkey.clone(),
        |a| a.ml_dsa_pubkey.clone(),
    );
    verify_request(
        &hdrs,
        &rec.agent_id,
        &pubkey,
        method.as_str(),
        path,
        body,
        now_ms(),
    )
    .map_err(|e| match e {
        AuthError::BadHeader(_) => (StatusCode::UNAUTHORIZED, format!("auth: {e}")).into_response(),
        _ => (StatusCode::FORBIDDEN, format!("auth: {e}")).into_response(),
    })?;
    Ok(rec)
}

fn unusable(why: &str) -> Response {
    tracing::warn!(why, "actor record unusable for auth");
    (StatusCode::FORBIDDEN, "actor record unusable").into_response()
}

/// Body of `POST /actors/:handle/following`.
#[derive(Deserialize)]
pub struct FollowBody {
    /// Remote actor URL the device just sent a `Follow` to.
    pub target_actor_url: String,
    /// That actor's inbox URL (kept for the eventual `Undo`).
    pub target_inbox_url: String,
    /// The activity id the device minted (inbound `Accept` matches it).
    pub follow_activity_id: String,
}

/// `POST /actors/:handle/following` — record a device-sent follow as
/// `pending`.
pub async fn record_follow(
    State(state): State<Arc<BridgeState>>,
    Path(handle): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = format!("/actors/{handle}/following");
    let rec = match auth_actor(&state, &handle, &headers, &Method::POST, &path, &body).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let Ok(req) = serde_json::from_slice::<FollowBody>(&body) else {
        return (StatusCode::BAD_REQUEST, "malformed body").into_response();
    };
    if url_invalid(&req.target_actor_url) || url_invalid(&req.target_inbox_url) {
        return (StatusCode::BAD_REQUEST, "target URLs must be https").into_response();
    }
    match state
        .store
        .follow_request(
            &rec.agent_id,
            &req.target_actor_url,
            &req.target_inbox_url,
            &req.follow_activity_id,
            now_ms(),
        )
        .await
    {
        Ok(FollowOutcome::Created) => (StatusCode::CREATED, "pending").into_response(),
        Ok(FollowOutcome::AlreadyPending) => (StatusCode::OK, "already pending").into_response(),
        Ok(FollowOutcome::AlreadyAccepted) => (StatusCode::OK, "already accepted").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "follow_request failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
        }
    }
}

/// Body of `POST /actors/:handle/unfollow`.
#[derive(Deserialize)]
pub struct UnfollowBody {
    /// Remote actor URL to stop following.
    pub target_actor_url: String,
}

/// `POST /actors/:handle/unfollow` — drop the row (the device has
/// already signed + delivered `Undo(Follow)`).
pub async fn unfollow(
    State(state): State<Arc<BridgeState>>,
    Path(handle): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = format!("/actors/{handle}/unfollow");
    let rec = match auth_actor(&state, &handle, &headers, &Method::POST, &path, &body).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let Ok(req) = serde_json::from_slice::<UnfollowBody>(&body) else {
        return (StatusCode::BAD_REQUEST, "malformed body").into_response();
    };
    match state
        .store
        .unfollow(&rec.agent_id, &req.target_actor_url)
        .await
    {
        Ok(Some(_)) => (StatusCode::OK, "removed").into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "not following").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "unfollow failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
        }
    }
}

/// `GET /actors/:handle/following` — owner-only list of follows with
/// state. (The PUBLIC AP `following` collection intentionally serves
/// only `totalItems`; who a user follows is their business.)
pub async fn following_list(
    State(state): State<Arc<BridgeState>>,
    Path(handle): Path<String>,
    headers: HeaderMap,
) -> Response {
    let path = format!("/actors/{handle}/following");
    let rec = match auth_actor(&state, &handle, &headers, &Method::GET, &path, b"").await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match state.store.following_list(&rec.agent_id).await {
        Ok(list) => {
            let items: Vec<_> = list
                .iter()
                .map(|f| {
                    json!({
                        "target_actor_url": f.target_actor_url,
                        "state": match f.state {
                            crate::store_follow::FollowState::Pending => "pending",
                            crate::store_follow::FollowState::Accepted => "accepted",
                        },
                        "follow_activity_id": f.follow_activity_id,
                        "created_ms": f.created_ms,
                    })
                })
                .collect();
            Json(json!({ "items": items })).into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "following_list failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
        }
    }
}

/// Body of `POST /actors/:handle/followers/confirm`.
#[derive(Deserialize)]
pub struct ConfirmFollowerBody {
    /// The remote actor now following us.
    pub follower_actor_url: String,
    /// Their inbox (post fan-out target).
    pub follower_inbox_url: String,
}

/// `POST /actors/:handle/followers/confirm` — the device delivered its
/// signed `Accept`; record the follower.
pub async fn confirm_follower(
    State(state): State<Arc<BridgeState>>,
    Path(handle): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = format!("/actors/{handle}/followers/confirm");
    let rec = match auth_actor(&state, &handle, &headers, &Method::POST, &path, &body).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let Ok(req) = serde_json::from_slice::<ConfirmFollowerBody>(&body) else {
        return (StatusCode::BAD_REQUEST, "malformed body").into_response();
    };
    if url_invalid(&req.follower_actor_url) || url_invalid(&req.follower_inbox_url) {
        return (StatusCode::BAD_REQUEST, "follower URLs must be https").into_response();
    }
    match state
        .store
        .add_follower(
            &rec.agent_id,
            &req.follower_actor_url,
            &req.follower_inbox_url,
            now_ms(),
        )
        .await
    {
        Ok(true) => (StatusCode::CREATED, "recorded").into_response(),
        Ok(false) => (StatusCode::OK, "already recorded").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "add_follower failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
        }
    }
}

/// v1 URL sanity: absolute `https` with a host. (Full SSRF guarding
/// applies where the bridge FETCHES; these URLs are only stored and
/// echoed back to the owning client.)
fn url_invalid(s: &str) -> bool {
    match url::Url::parse(s) {
        Ok(u) => u.scheme() != "https" || u.host_str().is_none(),
        Err(_) => true,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn url_sanity() {
        assert!(!url_invalid("https://fosstodon.org/users/happyborg"));
        assert!(url_invalid("http://fosstodon.org/users/happyborg"));
        assert!(url_invalid("not a url"));
        assert!(url_invalid("file:///etc/passwd"));
    }
}
