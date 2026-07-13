//! Inbound fediverse delivery (M7 P3-inbound).
//!
//! `POST /actors/:handle/inbox` is where remote servers deliver to a
//! registered actor. Unlike the follow-state routes (which run
//! `bridge-auth-v1` over OUR agent key), inbound activities are signed
//! by the REMOTE sender's RSA key, so the gate here is an HTTP-Signature
//! verify against the sender's fetched public key — exactly the
//! Mastodon-federation contract.
//!
//! Accepted activities:
//! * `Create(Note)` addressed to the recipient → stored as an inbox
//!   message (the reply the app renders in the fedi thread). The Note's
//!   HTML is reduced to plain text before storage; raw remote markup is
//!   never persisted.
//! * `Accept(Follow)` echoing one of our `Follow` ids → flips the
//!   following row to `accepted`.
//!
//! Everything else is acknowledged with `202` and ignored (a fediverse
//! inbox must not 4xx on activity types it doesn't handle, or senders
//! retry forever).
//!
//! The companion owner-only read route `GET /actors/:handle/messages`
//! runs `bridge-auth-v1` (only the handle's owner reads its inbox) and
//! serves stored messages after a `since_ms` cursor.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use fetchit_fedi::signature::{compute_content_digest, verify_signature_rfc9421};
use fetchit_fedi::signature_cavage::{
    compute_digest_cavage, parse_cavage_signature_header, verify_signature_cavage,
};
use serde::Deserialize;
use serde_json::{json, Value};

use fetchit_fedi::actor::Actor;

use crate::auth::{parse_headers, verify_request, AuthError};
use crate::server::BridgeState;
use crate::store::{ActorRecord, InboxMessage};

/// Cap on an accepted inbound body. Mastodon Notes are small; a
/// multi-megabyte "activity" is abuse, not a message.
const MAX_INBOX_BODY: usize = 128 * 1024;
/// Max clock skew between the signer's `Date` header and our clock.
const MAX_DATE_SKEW_SECS: i64 = 12 * 60 * 60;

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// `POST /actors/:handle/inbox` — accept a signed inbound activity.
pub async fn post_inbox(
    State(state): State<Arc<BridgeState>>,
    Path(handle): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if body.len() > MAX_INBOX_BODY {
        return (StatusCode::PAYLOAD_TOO_LARGE, "activity too large").into_response();
    }
    // The recipient must be a handle we host.
    let rec = match state.store.actor_by_handle(&handle).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such actor").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response(),
    };
    let Ok(activity) = serde_json::from_slice::<Value>(&body) else {
        return (StatusCode::BAD_REQUEST, "malformed activity").into_response();
    };
    // The signer is the activity's `actor`; fetch their key (SSRF-guarded)
    // and verify the HTTP signature before trusting a single field.
    let Some(sender_url) = activity.get("actor").and_then(Value::as_str) else {
        return (StatusCode::BAD_REQUEST, "activity has no actor").into_response();
    };
    let Ok(sender_actor_url) = sender_url.parse::<url::Url>() else {
        return (StatusCode::BAD_REQUEST, "actor is not a url").into_response();
    };
    let Ok(sender) = fetchit_fedi::lookup::fetch_remote_actor(&sender_actor_url).await else {
        return (StatusCode::BAD_GATEWAY, "could not fetch sender").into_response();
    };
    let Some(pubkey_pem) = sender.rsa_public_key_pem.as_deref() else {
        return (StatusCode::UNAUTHORIZED, "sender has no key").into_response();
    };
    if let Err(reason) = verify_inbound_signature(&headers, &handle, pubkey_pem, &body) {
        return (StatusCode::UNAUTHORIZED, reason).into_response();
    }

    // Signature verified. Dispatch on activity type.
    match activity.get("type").and_then(Value::as_str) {
        Some("Create") => match handle_create(&state, &rec, sender.id.as_str(), &activity).await {
            Ok(()) => (StatusCode::ACCEPTED, "accepted").into_response(),
            Err(resp) => resp,
        },
        Some("Accept") => {
            handle_accept(&state, &activity).await;
            (StatusCode::ACCEPTED, "accepted").into_response()
        }
        // Unknown/unhandled types are acknowledged, never rejected.
        _ => (StatusCode::ACCEPTED, "ignored").into_response(),
    }
}

/// Verify the inbound HTTP signature over this request against
/// `pubkey_pem`. Supports both wire formats Mastodon-family servers
/// emit (RFC 9421 and draft-cavage). Returns a short reason string on
/// failure (surfaced as the 401 body).
fn verify_inbound_signature(
    headers: &HeaderMap,
    handle: &str,
    pubkey_pem: &str,
    body: &[u8],
) -> Result<(), &'static str> {
    let date = header(headers, "date").ok_or("missing date")?;
    check_date_skew(&date).map_err(|()| "stale date")?;
    let host = header(headers, "host").ok_or("missing host")?;
    let request_path = format!("/actors/{handle}/inbox");
    let pubkey =
        fetchit_fedi::signature::parse_rsa_public_key_pem(pubkey_pem).ok_or("bad sender key")?;

    if let Some(sig_input) = header(headers, "signature-input") {
        // RFC 9421.
        let signature = header(headers, "signature").ok_or("missing signature")?;
        let content_digest = header(headers, "content-digest").ok_or("missing content-digest")?;
        if compute_content_digest(body) != content_digest {
            return Err("digest mismatch");
        }
        let scheme = header(headers, "x-forwarded-proto").unwrap_or_else(|| "https".into());
        let fwd_host = header(headers, "x-forwarded-host").unwrap_or_else(|| host.clone());
        let target_uri = format!("{scheme}://{fwd_host}{request_path}");
        verify_signature_rfc9421(
            &pubkey,
            &target_uri,
            &host,
            &date,
            &content_digest,
            &sig_input,
            &signature,
            body,
        )
        .map_err(|_| "signature invalid")
    } else {
        // draft-cavage.
        let signature = header(headers, "signature").ok_or("missing signature")?;
        let digest = header(headers, "digest").ok_or("missing digest")?;
        if compute_digest_cavage(body) != digest {
            return Err("digest mismatch");
        }
        let parsed =
            parse_cavage_signature_header(&signature).map_err(|_| "malformed signature")?;
        if !parsed.algorithm.is_empty() && parsed.algorithm != "rsa-sha256" {
            return Err("unsupported algorithm");
        }
        let request_target = format!("post {request_path}");
        verify_signature_cavage(
            &pubkey,
            &request_target,
            &host,
            &date,
            &digest,
            &signature,
            body,
        )
        .map_err(|_| "signature invalid")
    }
}

/// A `Create(Note)`: reduce the Note to plain text and store it as an
/// inbox message for the recipient. Skips (still 202s) when the object
/// isn't a Note or carries no content — a fediverse inbox never 4xxes a
/// well-signed activity it merely doesn't render.
async fn handle_create(
    state: &BridgeState,
    rec: &ActorRecord,
    sender_actor_url: &str,
    activity: &Value,
) -> Result<(), Response> {
    let Some(note) = activity.get("object") else {
        return Ok(());
    };
    if note.get("type").and_then(Value::as_str) != Some("Note") {
        return Ok(());
    }
    let content_html = note
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let text = fetchit_fedi::text::html_to_text(content_html);
    if text.is_empty() {
        return Ok(());
    }
    let note_id = note
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if note_id.is_empty() {
        return Ok(());
    }
    let published = note
        .get("published")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let msg = InboxMessage {
        actor_id: rec.agent_id.clone(),
        sender_actor_url: sender_actor_url.to_owned(),
        note_id,
        text,
        published,
        created_ms: now_ms(),
    };
    state
        .store
        .inbox_insert(msg)
        .await
        .map(|_| ())
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response())
}

/// An `Accept(Follow)`: flip the matching following row to `accepted`.
/// The `object.id` echoes the `Follow` id we minted; matching on it
/// (not the sender's word) is what makes the confirmation trustworthy.
async fn handle_accept(state: &BridgeState, activity: &Value) {
    let follow_id = activity
        .get("object")
        .and_then(|o| o.get("id").and_then(Value::as_str).or_else(|| o.as_str()));
    if let Some(fid) = follow_id {
        let _ = state.store.follow_accepted(fid).await;
    }
}

/// Query for the owner-only inbox read route.
#[derive(Deserialize)]
pub struct MessagesQuery {
    /// Return messages strictly newer than this receive-time cursor.
    #[serde(default)]
    since_ms: i64,
}

/// `GET /actors/:handle/messages` — owner-only inbound message list.
/// Runs `bridge-auth-v1`: only the handle's registered owner reads it.
pub async fn get_messages(
    State(state): State<Arc<BridgeState>>,
    Path(handle): Path<String>,
    Query(q): Query<MessagesQuery>,
    headers: HeaderMap,
) -> Response {
    let path = format!("/actors/{handle}/messages");
    let rec = match auth_owner(&state, &handle, &headers, &Method::GET, &path, b"").await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match state.store.inbox_list(&rec.agent_id, q.since_ms, 200).await {
        Ok(list) => {
            let items: Vec<_> = list
                .iter()
                .map(|m| {
                    json!({
                        "sender_actor_url": m.sender_actor_url,
                        "note_id": m.note_id,
                        "text": m.text,
                        "published": m.published,
                        "created_ms": m.created_ms,
                    })
                })
                .collect();
            Json(json!({ "items": items })).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response(),
    }
}

/// `bridge-auth-v1` gate for an owner-only route (mirrors the follow
/// module's `auth_actor`; kept module-local to avoid a cross-module
/// pub-helper churn).
async fn auth_owner(
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
        Ok(None) => return Err((StatusCode::NOT_FOUND, "no such actor").into_response()),
        Err(_) => {
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response());
        }
    };
    let doc: Value = serde_json::from_str(&rec.doc_json)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "corrupt doc").into_response())?;
    let actor = Actor::from_json_ld(&doc)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "corrupt doc").into_response())?;
    // Prefer the v2 attestation key; fall back to the required v1.
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
        now_ms_u64(),
    )
    .map_err(|e| match e {
        AuthError::BadHeader(_) => (StatusCode::UNAUTHORIZED, format!("auth: {e}")).into_response(),
        _ => (StatusCode::FORBIDDEN, format!("auth: {e}")).into_response(),
    })?;
    Ok(rec)
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

fn now_ms_u64() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Reject a `Date` header outside +/- [`MAX_DATE_SKEW_SECS`] of now.
fn check_date_skew(date: &str) -> Result<(), ()> {
    let signed = fetchit_fedi::transport::parse_imf_fixdate(date).ok_or(())?;
    let signed_secs = i64::try_from(
        signed
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ())?
            .as_secs(),
    )
    .map_err(|_| ())?;
    let now_secs = now_ms() / 1000;
    if (now_secs - signed_secs).abs() > MAX_DATE_SKEW_SECS {
        return Err(());
    }
    Ok(())
}
