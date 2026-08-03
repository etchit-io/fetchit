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
    compute_digest_cavage, parse_cavage_signature_header, verify_signature_cavage_declared,
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
    let sender = match fetchit_fedi::lookup::fetch_remote_actor(&sender_actor_url).await {
        Ok(s) => s,
        Err(e) => {
            // A Delete whose sender is AUTHORITATIVELY gone (account
            // erased — the 2026-08-02 drops were 410 tombstones) is
            // unverifiable BY DESIGN: the signing key died with the
            // account, and we hold no state for an unknown actor.
            // Acknowledge it so the remote stops retrying for two days.
            // Every transient failure class (timeout, 5xx, DNS, parse)
            // stays a retryable 502 for EVERY activity type, Delete
            // included — a momentary outage must never eat a delivery
            // (cross-review 2026-08-03 finding 3).
            if gone_delete_shortcut(&e, &activity) {
                tracing::info!(handle, sender = %sender_actor_url, "unverifiable Delete from gone sender ignored");
                return (StatusCode::ACCEPTED, "ignored").into_response();
            }
            tracing::warn!(handle, sender = %sender_actor_url, error = %e, "inbox: could not fetch sender actor");
            return (StatusCode::BAD_GATEWAY, "could not fetch sender").into_response();
        }
    };
    let Some(pubkey_pem) = sender.rsa_public_key_pem.as_deref() else {
        tracing::warn!(handle, sender = %sender_actor_url, "inbox: sender has no key");
        return (StatusCode::UNAUTHORIZED, "sender has no key").into_response();
    };
    if let Err(reason) =
        verify_inbound_signature(&headers, &handle, pubkey_pem, &body, &state.config.domain)
    {
        // A rejected delivery is invisible to both ends without this line —
        // the 2026-07-13 lost-Accept class was undiagnosable from logs.
        tracing::warn!(handle, sender = %sender_actor_url, reason, "inbox: signature rejected");
        return (StatusCode::UNAUTHORIZED, reason).into_response();
    }

    // Signature verified. Dispatch on activity type.
    let activity_type = activity.get("type").and_then(Value::as_str);
    tracing::info!(handle, sender = %sender_actor_url, activity_type, "inbox: verified delivery");
    match activity_type {
        Some("Create") => match handle_create(&state, &rec, sender.id.as_str(), &activity).await {
            Ok(()) => (StatusCode::ACCEPTED, "accepted").into_response(),
            Err(resp) => resp,
        },
        Some("Accept") => {
            handle_accept(&state, &rec, sender.id.as_str(), &activity).await;
            (StatusCode::ACCEPTED, "accepted").into_response()
        }
        Some("Reject") => {
            handle_reject(&state, sender.id.as_str(), &activity).await;
            (StatusCode::ACCEPTED, "accepted").into_response()
        }
        Some("Follow") => {
            handle_follow(&state, &rec, &sender, &activity).await;
            (StatusCode::ACCEPTED, "accepted").into_response()
        }
        Some("Undo") => {
            handle_undo(&state, &rec, sender.id.as_str(), &activity).await;
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
///
/// `public_host` is the fediverse domain this bridge is authoritative
/// for (`config.domain`). Remote signers sign the `host` from our
/// advertised inbox URL — `etchit.io` — while the edge worker forwards
/// to the origin vhost, so the received `Host` header names the WRONG
/// host for signature reconstruction. Both candidates are tried,
/// public domain first (the 2026-07-14 zero-stored-replies root
/// cause, one of two: the fixed-base cavage verifier that ignored the
/// signer's declared header list was the other).
fn verify_inbound_signature(
    headers: &HeaderMap,
    handle: &str,
    pubkey_pem: &str,
    body: &[u8],
    public_host: &str,
) -> Result<(), &'static str> {
    let date = header(headers, "date").ok_or("missing date")?;
    check_date_skew(&date).map_err(|()| "stale date")?;
    let host = header(headers, "host").ok_or("missing host")?;
    let host_candidates = [public_host, host.as_str()];
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
        for candidate in dedup_two(&host_candidates) {
            let target_uri = format!("{scheme}://{candidate}{request_path}");
            if verify_signature_rfc9421(
                &pubkey,
                &target_uri,
                candidate,
                &date,
                &content_digest,
                &sig_input,
                &signature,
                body,
            )
            .is_ok()
            {
                return Ok(());
            }
        }
        Err("signature invalid")
    } else {
        // draft-cavage — verified over the signer's DECLARED header
        // list (Mastodon signs `(request-target) host date digest
        // content-type`), never a fixed base.
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
        verify_signature_cavage_declared(
            &pubkey,
            "post",
            &request_path,
            &host_candidates,
            &|name| header(headers, name),
            &signature,
        )
        .map_err(|e| match e {
            fetchit_fedi::signature::SignatureVerifyError::MissingSignedHeader(_) => {
                "signed header missing from request"
            }
            _ => "signature invalid",
        })
    }
}

/// The two host candidates with an equal pair collapsed to one, so the
/// common direct-to-origin case costs a single verification.
fn dedup_two<'a>(candidates: &'a [&'a str; 2]) -> impl Iterator<Item = &'a str> {
    let dup = candidates[0] == candidates[1];
    candidates.iter().take(if dup { 1 } else { 2 }).copied()
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
    // Only DIRECT messages belong in the DM inbox. A followed account's
    // public posts (and its public @-replies to third parties) are also
    // delivered here — that is how ActivityPub push works — but they are
    // public timeline content, not private mail, and must never render
    // as a DM. Public/unlisted/followers-only notes are dropped (the
    // client feed surface pulls public posts from outboxes); only a note
    // addressed specifically to us, with no public/followers audience,
    // is stored.
    if !is_direct_to(note, &rec.actor_url) {
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

/// The `as:Public` collection aliases that mark a note public (or, in
/// `cc` only, unlisted). Any of these anywhere in the audience means the
/// note is not private.
const PUBLIC_ALIASES: [&str; 3] = [
    "https://www.w3.org/ns/activitystreams#Public",
    "as:Public",
    "Public",
];

/// Collect the string URIs from an `ActivityPub` addressing field, which
/// may be a single string or an array of strings (both are valid).
fn audience_uris(field: Option<&Value>) -> Vec<&str> {
    match field {
        Some(Value::String(s)) => vec![s.as_str()],
        Some(Value::Array(arr)) => arr.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

/// Is `note` a direct message addressed to `our_actor_url`?
///
/// True only when the combined `to`+`cc` audience (a) contains no
/// `as:Public` alias (rules out public and unlisted), (b) contains no
/// followers-collection URI — a `.../followers` broadcast — (rules out
/// followers-only), and (c) actually names our actor. This is the same
/// visibility a Mastodon receiver computes; anything else is timeline
/// content that must not enter the DM inbox.
fn is_direct_to(note: &Value, our_actor_url: &str) -> bool {
    let mut audience = audience_uris(note.get("to"));
    audience.extend(audience_uris(note.get("cc")));
    if audience.iter().any(|u| PUBLIC_ALIASES.contains(u)) {
        return false;
    }
    if audience.iter().any(|u| u.ends_with("/followers")) {
        return false;
    }
    audience.contains(&our_actor_url)
}

/// An `Accept(Follow)`: flip the matching following row to `accepted`.
///
/// The `object.id` echoes the `Follow` id we minted, but matching on it
/// ALONE is not enough — the id rides the `Follow` we deliver, so it is
/// not secret. The store bind requires the signature-verified sender
/// (`sender_id`, already authenticated by the inbox HTTP-Signature check)
/// to be the actor the row follows, and the recipient handle
/// (`rec.agent_id`) to own the row. A forged or cross-account `Accept`
/// therefore flips nothing.
async fn handle_accept(
    state: &BridgeState,
    rec: &crate::store::ActorRecord,
    sender_id: &str,
    activity: &Value,
) {
    let follow_id = activity
        .get("object")
        .and_then(|o| o.get("id").and_then(Value::as_str).or_else(|| o.as_str()));
    if let Some(fid) = follow_id {
        match state
            .store
            .follow_accepted(fid, sender_id, &rec.agent_id)
            .await
        {
            Ok(true) => tracing::info!(handle = %rec.handle, follow_id = fid, "follow accepted"),
            Ok(false) => tracing::warn!(
                handle = %rec.handle,
                sender = sender_id,
                follow_id = fid,
                "accept matched no pending follow (stale, duplicate, or forged)"
            ),
            Err(e) => tracing::warn!(error = %e, "follow_accepted store failure"),
        }
    }
}

/// A `Reject(Follow)`: the remote side refused our follow — drop the
/// pending row, bound to the signature-verified sender so a third party
/// cannot drop a follow they are not the target of.
async fn handle_reject(state: &BridgeState, sender_id: &str, activity: &Value) {
    let follow_id = activity
        .get("object")
        .and_then(|o| o.get("id").and_then(Value::as_str).or_else(|| o.as_str()));
    if let Some(fid) = follow_id {
        match state.store.follow_rejected(fid, sender_id).await {
            Ok(true) => tracing::info!(sender = sender_id, follow_id = fid, "follow rejected"),
            Ok(false) => tracing::warn!(
                sender = sender_id,
                follow_id = fid,
                "reject matched no follow (stale or forged)"
            ),
            Err(e) => tracing::warn!(error = %e, "follow_rejected store failure"),
        }
    }
}

/// An inbound `Follow` of one of our actors: queue it for the owner
/// device, which signs the `Accept` (the bridge holds no keys), delivers
/// it, and confirms the follower.
///
/// The `object` must be OUR actor — a signature-verified sender asking
/// to follow someone else does not belong in this queue. The activity
/// `id` is required: the device's `Accept` must echo it or the remote
/// side cannot correlate the answer.
async fn handle_follow(
    state: &BridgeState,
    rec: &crate::store::ActorRecord,
    sender: &fetchit_fedi::lookup::RemoteActor,
    activity: &Value,
) {
    let object = activity
        .get("object")
        .and_then(|o| o.get("id").and_then(Value::as_str).or_else(|| o.as_str()));
    if object != Some(rec.actor_url.as_str()) {
        tracing::warn!(handle = %rec.handle, ?object, "follow object is not this actor; ignored");
        return;
    }
    let Some(follow_id) = activity.get("id").and_then(Value::as_str) else {
        tracing::warn!(handle = %rec.handle, sender = %sender.id, "follow has no id; ignored");
        return;
    };
    match state
        .store
        .add_follow_request(
            &rec.agent_id,
            sender.id.as_str(),
            sender.inbox.as_str(),
            follow_id,
            u64::try_from(now_ms()).unwrap_or(0),
        )
        .await
    {
        Ok(()) => {
            tracing::info!(handle = %rec.handle, sender = %sender.id, "follow request queued");
        }
        Err(e) => tracing::warn!(error = %e, "add_follow_request store failure"),
    }
}

/// An `Undo(Follow)`: the sender retracts their follow of our actor —
/// drop both the queued request (if unanswered) and the follower row.
/// Only an embedded `Follow` object whose `actor` is the
/// signature-verified sender and whose `object` is our actor counts;
/// `Undo` of anything else is ignored.
async fn handle_undo(
    state: &BridgeState,
    rec: &crate::store::ActorRecord,
    sender_id: &str,
    activity: &Value,
) {
    let Some(object) = activity.get("object") else {
        return;
    };
    let is_follow_of_us = object.get("type").and_then(Value::as_str) == Some("Follow")
        && object.get("actor").and_then(Value::as_str) == Some(sender_id)
        && object.get("object").and_then(Value::as_str) == Some(rec.actor_url.as_str());
    if !is_follow_of_us {
        return;
    }
    let dropped_request = state
        .store
        .remove_follow_request(&rec.agent_id, sender_id, None)
        .await
        .unwrap_or(false);
    let dropped_follower = state
        .store
        .remove_follower(&rec.agent_id, sender_id)
        .await
        .unwrap_or(false);
    tracing::info!(
        handle = %rec.handle,
        sender = sender_id,
        dropped_request,
        dropped_follower,
        "undo(follow) processed"
    );
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

/// True only for the one acknowledged-drop shape: a `Delete` activity
/// whose sender fetch failed with an authoritative not-found (404) or
/// tombstone (410). Every other failure is possibly transient and the
/// caller must keep the delivery retryable.
fn gone_delete_shortcut(err: &fetchit_fedi::actor::FetchActorError, activity: &Value) -> bool {
    let authoritative_gone = matches!(
        err,
        fetchit_fedi::actor::FetchActorError::Http {
            status: 404 | 410,
            ..
        }
    );
    authoritative_gone && activity.get("type").and_then(Value::as_str) == Some("Delete")
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::RsaPrivateKey;
    use sha2::Sha256;

    /// A request exactly as prod receives a Mastodon delivery: signed
    /// over the PUBLIC domain and Mastodon's 5-header list, arriving
    /// with the edge-worker's ORIGIN vhost in `Host`.
    fn mastodon_delivery() -> (HeaderMap, Vec<u8>, String) {
        let priv_key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
        let pubkey_pem = priv_key
            .to_public_key()
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();
        let body = br#"{"type":"Create","actor":"https://fosstodon.org/users/happyborg"}"#.to_vec();
        let date = fetchit_fedi::transport::format_imf_fixdate(std::time::SystemTime::now());
        let digest = compute_digest_cavage(&body);
        let base = format!(
            "(request-target): post /actors/josh/inbox\n\
             host: etchit.io\n\
             date: {date}\n\
             digest: {digest}\n\
             content-type: application/activity+json"
        );
        let signing_key = SigningKey::<Sha256>::new(priv_key);
        let sig = B64.encode(signing_key.sign(base.as_bytes()).to_bytes());
        let signature = format!(
            "keyId=\"https://fosstodon.org/users/happyborg#main-key\",\
             algorithm=\"rsa-sha256\",\
             headers=\"(request-target) host date digest content-type\",\
             signature=\"{sig}\""
        );

        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("bridge-origin.etchit.io"));
        headers.insert("date", HeaderValue::from_str(&date).unwrap());
        headers.insert("digest", HeaderValue::from_str(&digest).unwrap());
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/activity+json"),
        );
        headers.insert("signature", HeaderValue::from_str(&signature).unwrap());
        (headers, body, pubkey_pem)
    }

    #[test]
    fn mastodon_shaped_delivery_verifies_behind_edge_worker() {
        // The exact prod scenario that produced zero stored replies:
        // Mastodon's declared header list (with content-type) plus the
        // origin-vhost Host header. Both killers at once.
        let (headers, body, pubkey_pem) = mastodon_delivery();
        verify_inbound_signature(&headers, "josh", &pubkey_pem, &body, "etchit.io")
            .expect("a real Mastodon delivery must verify through the edge topology");
    }

    #[test]
    fn wrong_public_host_still_fails() {
        // Sanity: candidates don't make verification lax — a signature
        // over a host we never advertise stays rejected.
        let (headers, body, pubkey_pem) = mastodon_delivery();
        assert!(
            verify_inbound_signature(&headers, "josh", &pubkey_pem, &body, "evil.example").is_err(),
            "signature bound to etchit.io must not verify for evil.example + origin vhost",
        );
    }

    #[test]
    fn tampered_body_fails_digest_gate() {
        let (headers, _body, pubkey_pem) = mastodon_delivery();
        let err = verify_inbound_signature(&headers, "josh", &pubkey_pem, b"{}", "etchit.io")
            .unwrap_err();
        assert_eq!(err, "digest mismatch");
    }

    const OURS: &str = "https://etchit.io/actors/josh";

    #[test]
    fn direct_note_addressed_only_to_us_is_a_dm() {
        // A true DM: to = [us], no public, no followers.
        let note = json!({ "to": [OURS], "cc": [] });
        assert!(is_direct_to(&note, OURS));
    }

    #[test]
    fn public_post_mentioning_us_is_not_a_dm() {
        // The exact prod shape of the "hi, in case PMs aren't landing"
        // post: to includes #Public, cc includes followers + us. Public
        // timeline content, not a DM — must be dropped.
        let note = json!({
            "to": ["https://www.w3.org/ns/activitystreams#Public"],
            "cc": ["https://fosstodon.org/users/happyborg/followers", OURS],
        });
        assert!(!is_direct_to(&note, OURS));
    }

    #[test]
    fn unlisted_post_public_in_cc_is_not_a_dm() {
        let note = json!({
            "to": [OURS],
            "cc": ["https://www.w3.org/ns/activitystreams#Public"],
        });
        assert!(!is_direct_to(&note, OURS));
    }

    #[test]
    fn followers_only_broadcast_is_not_a_dm() {
        let note = json!({
            "to": ["https://fosstodon.org/users/happyborg/followers", OURS],
            "cc": [],
        });
        assert!(!is_direct_to(&note, OURS));
    }

    #[test]
    fn direct_note_not_addressed_to_us_is_not_ours() {
        // A DM between two other actors that somehow reached us: not
        // addressed to our actor, so not stored.
        let note = json!({ "to": ["https://fosstodon.org/users/someone"], "cc": [] });
        assert!(!is_direct_to(&note, OURS));
    }

    #[test]
    fn bare_public_string_alias_is_not_a_dm() {
        // `to` as a single string, and the short "Public" alias.
        let note = json!({ "to": "Public", "cc": OURS });
        assert!(!is_direct_to(&note, OURS));
    }

    #[test]
    fn to_as_single_string_direct_is_a_dm() {
        let note = json!({ "to": OURS });
        assert!(is_direct_to(&note, OURS));
    }

    #[test]
    fn gone_delete_shortcut_fires_only_on_authoritative_gone_plus_delete() {
        use fetchit_fedi::actor::FetchActorError;
        let gone = FetchActorError::Http {
            status: 410,
            body: "Gone".into(),
        };
        let missing = FetchActorError::Http {
            status: 404,
            body: "Not Found".into(),
        };
        let flaky = FetchActorError::Http {
            status: 503,
            body: "maintenance".into(),
        };
        let transport = FetchActorError::Transport("dns timeout".into());
        let delete = json!({ "type": "Delete" });
        let follow = json!({ "type": "Follow" });

        assert!(gone_delete_shortcut(&gone, &delete));
        assert!(gone_delete_shortcut(&missing, &delete));
        assert!(
            !gone_delete_shortcut(&gone, &follow),
            "a Follow from a gone sender is not the acknowledged shape"
        );
        assert!(
            !gone_delete_shortcut(&flaky, &delete),
            "5xx is transient — the Delete must stay retryable"
        );
        assert!(
            !gone_delete_shortcut(&transport, &delete),
            "transport failure is transient — the Delete must stay retryable"
        );
    }
}
