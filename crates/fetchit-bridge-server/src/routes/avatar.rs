//! Own-avatar hosting: the bytes an actor's `icon` URL points at.
//!
//! * `GET    /actors/:handle/avatar` — public, unauthenticated. This is
//!   the URL published in the actor document, so every fediverse server
//!   that renders the account fetches it.
//! * `POST   /actors/:handle/avatar` — `bridge-auth-v1`; only the
//!   registered owner of the handle can set their own picture.
//! * `DELETE /actors/:handle/avatar` — same auth; clears it.
//!
//! Three rules the handlers exist to hold:
//!
//! 1. **Never decode.** Bytes are stored and served verbatim. The
//!    allowlist + magic check confirm the shape of the first few bytes;
//!    nothing hands an image parser attacker input.
//! 2. **Never host anything but an image.** The declared `Content-Type`
//!    must be in [`UPLOADABLE_AVATAR_CONTENT_TYPES`] AND the bytes must
//!    open with that format's magic — otherwise this endpoint would let
//!    any registered user park arbitrary content under our domain.
//! 3. **Never sniff on the way out.** Responses carry the stored type
//!    plus `X-Content-Type-Options: nosniff`, so a browser cannot be
//!    talked into treating an avatar as markup.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use fetchit_fedi::avatar::{
    magic_matches_content_type, normalize_content_type, UPLOADABLE_AVATAR_CONTENT_TYPES,
};

use crate::routes::follow::auth_actor;
use crate::server::BridgeState;

/// How long a served avatar may be reused before revalidating. The URL
/// is stable across picture changes, so this is the worst-case lag
/// between someone changing their photo and a cache showing it — five
/// minutes, rather than the day-long lifetime a content-addressed URL
/// could afford.
const AVATAR_MAX_AGE_SECS: u32 = 300;

/// `GET /actors/:handle/avatar` — the stored image, or 404.
///
/// Public by design: it is the `icon` URL in a public actor document.
/// A missing handle and a handle with no picture both answer 404;
/// distinguishing them would only tell a prober which handles exist,
/// which the actor document already tells them anyway, so the simpler
/// shape wins.
pub async fn get_avatar(
    State(state): State<Arc<BridgeState>>,
    Path(handle): Path<String>,
) -> Response {
    match state.store.avatar_by_handle(&handle).await {
        Ok(Some(avatar)) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, avatar.content_type),
                (
                    header::CACHE_CONTROL,
                    format!("public, max-age={AVATAR_MAX_AGE_SECS}"),
                ),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_owned()),
            ],
            avatar.bytes,
        )
            .into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "no avatar").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "avatar_by_handle failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
        }
    }
}

/// `POST /actors/:handle/avatar` — set the picture. Body is the raw
/// image; `Content-Type` declares its format.
///
/// The body cap is a router layer ([`crate::server`]), so an oversized
/// upload is rejected as `413` before this handler allocates it.
pub async fn post_avatar(
    State(state): State<Arc<BridgeState>>,
    Path(handle): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = format!("/actors/{handle}/avatar");
    let rec = match auth_actor(&state, &handle, &headers, &Method::POST, &path, &body).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // Auth first, then shape: an unauthenticated caller learns nothing
    // about what this endpoint accepts.
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(normalize_content_type)
        .unwrap_or_default();
    if !UPLOADABLE_AVATAR_CONTENT_TYPES.contains(&content_type.as_str()) {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "content-type must be image/jpeg, image/png, or image/webp",
        )
            .into_response();
    }
    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, "empty body").into_response();
    }
    if !magic_matches_content_type(&content_type, &body) {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "body does not match the declared image type",
        )
            .into_response();
    }

    match state
        .store
        .set_avatar(&rec.agent_id, body.to_vec(), &content_type)
        .await
    {
        Ok(true) => (StatusCode::OK, "avatar set").into_response(),
        // Unreachable: auth_actor resolved the row this update targets.
        Ok(false) => (StatusCode::NOT_FOUND, "unknown handle").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "set_avatar failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
        }
    }
}

/// `DELETE /actors/:handle/avatar` — clear the picture. Idempotent: a
/// delete with nothing to delete still answers 200, so a client
/// retrying after a dropped response needs no special case.
pub async fn delete_avatar(
    State(state): State<Arc<BridgeState>>,
    Path(handle): Path<String>,
    headers: HeaderMap,
) -> Response {
    let path = format!("/actors/{handle}/avatar");
    let rec = match auth_actor(&state, &handle, &headers, &Method::DELETE, &path, b"").await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match state.store.clear_avatar(&rec.agent_id).await {
        Ok(true) => (StatusCode::OK, "avatar cleared").into_response(),
        Ok(false) => (StatusCode::OK, "no avatar").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "clear_avatar failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
        }
    }
}
