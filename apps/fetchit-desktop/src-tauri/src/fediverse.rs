//! M4 fediverse compose half: actor-mint onboarding + public-post
//! publish commands. The read side (the `fediverse:post` subscription
//! pump) lives in `chat.rs::spawn_public_posts`; this module is the
//! outbound counterpart, gated by the same chat feature flag.

use crate::chat::{ensure_chat_enabled, ChatState};
use crate::state::AppState;
use serde::Serialize;

/// Fediverse host whose `WebFinger` directory publishes minted actors.
/// The bridge relay serves this domain once relay TLS + DNS land; the
/// chat crate constructs `https://<domain>/actors/<handle>` from it.
pub const DEFAULT_FEDI_DOMAIN: &str = "etchit.io";

/// Outcome of a publish, mirrored from `fetchit_chat::PublishReport`
/// for the frontend's honest result line.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishReportDto {
    /// Inbox URLs that accepted the activity.
    pub delivered: Vec<String>,
    /// `(target, error)` per recipient that failed.
    pub failed: Vec<(String, String)>,
}

/// The active minted handle, or `None` when the user has not opted in
/// to public posting. Reads the persisted setting only — no chat-state
/// spin-up, so the pane can query it before chat connects.
#[tauri::command]
pub fn fediverse_actor_status(state: tauri::State<'_, AppState>) -> Option<String> {
    let handle = state
        .settings
        .lock()
        .ok()
        .map(|s| s.fediverse_handle.clone())?;
    if handle.is_empty() {
        None
    } else {
        Some(handle)
    }
}

/// Result of a mint: the identity is always created locally; directory
/// registration is best-effort and reported honestly.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MintOutcomeDto {
    /// Canonical actor URL.
    pub actor_url: String,
    /// True when the etchit.io directory accepted the registration.
    pub registered: bool,
    /// Why registration is pending, when it is.
    pub registration_error: Option<String>,
}

/// Result of the v2 upgrade pass run on pane open.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnsureV2Dto {
    /// True when a fresh v2 attestation was signed and stored.
    pub upgraded: bool,
    /// True when the directory holds the current record.
    pub registered: bool,
    /// Why the pass could not complete (profile unpublished, bridge
    /// unreachable); user-facing copy.
    pub pending: Option<String>,
}

/// Milliseconds since the epoch (same construction `fediverse_publish`
/// uses for `created_at_ms`).
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Best-effort directory registration. Mint stays local-first: a
/// bridge outage degrades to "registration pending", never a failed
/// mint. POST then PUT on 409 so re-asserting our own handle after an
/// attestation refresh self-heals (a true squat by another agent fails
/// the PUT's same-agent-id continuity check and surfaces honestly).
async fn register_with_directory(
    identity: &fetchit_fedi::actor::ActorIdentity,
) -> (bool, Option<String>) {
    let Some(att2) = identity.ml_dsa_attestation_v2.clone() else {
        return (false, Some("no v2 attestation on identity".into()));
    };
    let Ok(base) = url::Url::parse(&format!("https://{DEFAULT_FEDI_DOMAIN}/")) else {
        return (false, Some("bad registry base URL".into()));
    };
    let req = fetchit_fedi::registry::RegisterActorRequest {
        handle: identity.handle.clone(),
        rsa_spki_der: identity.spki_der.clone(),
        attestation_v2: att2,
    };
    let Ok(http) = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()
    else {
        return (false, Some("http client build failed".into()));
    };
    match fetchit_fedi::registry::register_actor(&base, &req, &http).await {
        Ok(_) => (true, None),
        Err(fetchit_fedi::registry::RegistryError::HandleTaken) => {
            match fetchit_fedi::registry::update_actor(&base, &req, &http).await {
                Ok(_) => (true, None),
                Err(e) => (false, Some(e.to_string())),
            }
        }
        Err(e) => (false, Some(e.to_string())),
    }
}

/// Opt in to public posting: mint the actor identity for `handle` and
/// persist it as the active handle. **One-tap:** a fresh identity with no
/// published profile no longer dead-ends — the engine publishes a minimal
/// handle-only profile itself (no etch/it round-trip, no wallet) and binds
/// it. Routes through the shared engine orchestration
/// [`fetchit_chat::Client::mint_and_register_actor`], so desktop and the
/// mobile FFI mint follow ONE path.
///
/// # Errors
/// Chat feature off, chat client unavailable, a transient relay error, or
/// the crate-side handle validation / mint / minimal-publish failing.
/// Directory registration failure is NOT an error; it lands in the DTO.
#[tauri::command]
pub async fn fediverse_mint(
    app_state: tauri::State<'_, AppState>,
    chat_state: tauri::State<'_, ChatState>,
    handle: String,
) -> Result<MintOutcomeDto, String> {
    ensure_chat_enabled(&app_state)?;
    // Handles are lowercase-canonical (SO-3): normalize user input once
    // here so the attestation, actor URL, vault path, and the stored
    // setting all agree. The crate's validate_actor_handle then rejects
    // anything still non-lowercase.
    let handle = handle.trim().to_lowercase();
    let relay = chat_state.relay_url();
    let registry = url::Url::parse(&format!("https://{DEFAULT_FEDI_DOMAIN}/"))
        .map_err(|e| format!("bad registry base URL: {e}"))?;
    // The engine client retains the runtime custody it was built with
    // (keychain or passphrase), so the actor vault seals under the same
    // master as the chat identity with no per-call threading.
    let client = chat_state.get().await?;
    let outcome = client
        .mint_and_register_actor(&handle, DEFAULT_FEDI_DOMAIN, &relay, &registry, now_ms())
        .await
        .map_err(|e| e.to_string())?;
    if let Ok(mut s) = app_state.settings.lock() {
        s.fediverse_handle = handle;
        if let Err(e) = s.save(&app_state.settings_path) {
            tracing::warn!("minted handle held in memory only; settings save failed: {e}");
        }
    }
    Ok(MintOutcomeDto {
        actor_url: outcome.actor_url,
        registered: outcome.registration.registered(),
        registration_error: outcome.registration.error_text(),
    })
}

/// Run on pane open when a handle exists: transparently upgrade a
/// pre-M5 (v1-only) identity to v2 and re-assert the directory record.
/// Never errors the pane for upgrade blockers: those land in
/// `pending`.
///
/// # Errors
/// Chat feature off, chat client unavailable, or vault access failing.
#[tauri::command]
pub async fn fediverse_ensure_v2(
    app_state: tauri::State<'_, AppState>,
    chat_state: tauri::State<'_, ChatState>,
) -> Result<EnsureV2Dto, String> {
    ensure_chat_enabled(&app_state)?;
    let handle = app_state
        .settings
        .lock()
        .map_err(|e| format!("settings lock poisoned: {e}"))?
        .fediverse_handle
        .clone();
    if handle.is_empty() {
        return Ok(EnsureV2Dto {
            upgraded: false,
            registered: false,
            pending: None,
        });
    }
    let (record, relay) = match crate::chat::self_profile_record(&chat_state).await {
        Ok(v) => v,
        Err(reason) => {
            return Ok(EnsureV2Dto {
                upgraded: false,
                registered: false,
                pending: Some(reason),
            })
        }
    };
    let client = chat_state.get().await?;
    let upgraded = client
        .upgrade_actor_attestation_v2(&handle, &record.profile_addr, relay.as_str(), now_ms())
        .await
        .map_err(|e| e.to_string())?;
    let identity = client
        .load_actor_identity(&handle)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no actor identity for {handle}"))?;
    let (registered, err) = register_with_directory(&identity).await;
    Ok(EnsureV2Dto {
        upgraded,
        registered,
        pending: err,
    })
}

/// Publish a public post as the active handle. Mentions are extracted
/// from `body_md` (`@user@host` tokens); the chat crate resolves them
/// via `WebFinger` and runs denylist gating before any delivery.
///
/// # Errors
/// Chat feature off, no handle minted, or the publish itself failing
/// before any delivery was attempted.
#[tauri::command]
pub async fn fediverse_publish(
    app_state: tauri::State<'_, AppState>,
    chat_state: tauri::State<'_, ChatState>,
    body_md: String,
    reply_to_actor_url: Option<String>,
) -> Result<PublishReportDto, String> {
    ensure_chat_enabled(&app_state)?;
    let handle = app_state
        .settings
        .lock()
        .map_err(|e| format!("settings lock poisoned: {e}"))?
        .fediverse_handle
        .clone();
    if handle.is_empty() {
        return Err("no public handle minted".into());
    }
    let created_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let post = fetchit_fedi::PublicPost {
        author_handle: format!("@{handle}@{DEFAULT_FEDI_DOMAIN}"),
        body_md: body_md.clone(),
        created_at_ms,
        reply_to_actor_url,
        mentions: extract_mentions(&body_md),
    };
    let client = chat_state.get().await?;
    let report = client
        .publish_public_post(&handle, &post)
        .await
        .map_err(|e| e.to_string())?;
    Ok(PublishReportDto {
        delivered: report.delivered,
        failed: report.failed,
    })
}

/// Collect well-formed `@user@host` mentions from whitespace-split
/// tokens, dropping wrapping punctuation and duplicates while keeping
/// first-seen order. `fetchit_fedi::parse_mention` is the validity
/// oracle so extraction never drifts from publish-time resolution.
fn extract_mentions(body: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for token in body.split_whitespace() {
        let t = token
            .trim_start_matches(['(', '[', '{', '"', '\''])
            .trim_end_matches(['.', ',', '!', '?', ';', ':', ')', ']', '}', '"', '\'']);
        if !t.starts_with('@') || fetchit_fedi::parse_mention(t).is_err() {
            continue;
        }
        if !out.iter().any(|m| m == t) {
            out.push(t.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn extract_mentions_finds_a_plain_mention() {
        assert_eq!(
            extract_mentions("hi @bob@relay.example nice post"),
            vec!["@bob@relay.example"]
        );
    }

    #[test]
    fn extract_mentions_strips_wrapping_punctuation() {
        assert_eq!(
            extract_mentions("(@bob@relay.example), meet @ann@x.io!"),
            vec!["@bob@relay.example", "@ann@x.io"]
        );
    }

    #[test]
    fn extract_mentions_dedups_keeping_first_seen_order() {
        assert_eq!(
            extract_mentions("@bob@relay.example again @bob@relay.example"),
            vec!["@bob@relay.example"]
        );
    }

    #[test]
    fn extract_mentions_ignores_non_mention_noise() {
        let none: Vec<String> = Vec::new();
        assert_eq!(
            extract_mentions("email me @ home or user@host.com or @bare"),
            none
        );
    }

    #[test]
    fn publish_report_dto_serializes_camel_case() {
        let dto = PublishReportDto {
            delivered: vec!["https://a/inbox".into()],
            failed: vec![("https://b/inbox".into(), "410".into())],
        };
        let v = serde_json::to_value(&dto).unwrap();
        assert!(v.get("delivered").is_some());
        assert!(v.get("failed").is_some());
    }

    #[test]
    fn mint_outcome_dto_serializes_camel_case() {
        let dto = MintOutcomeDto {
            actor_url: "https://etchit.io/actors/josh".into(),
            registered: false,
            registration_error: Some("connection refused".into()),
        };
        let v = serde_json::to_value(&dto).unwrap();
        assert!(v.get("actorUrl").is_some());
        assert_eq!(v["registered"], false);
        assert_eq!(v["registrationError"], "connection refused");
    }

    #[test]
    fn ensure_v2_dto_serializes_camel_case() {
        let dto = EnsureV2Dto {
            upgraded: true,
            registered: false,
            pending: None,
        };
        let v = serde_json::to_value(&dto).unwrap();
        assert_eq!(v["upgraded"], true);
        assert_eq!(v["registered"], false);
        assert!(v["pending"].is_null());
    }
}
