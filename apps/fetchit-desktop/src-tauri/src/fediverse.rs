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

/// Opt in to public posting: mint the actor identity for `handle` and
/// persist it as the active handle. Returns the canonical actor URL.
///
/// # Errors
/// Chat feature off, chat client unavailable, or the crate-side handle
/// validation / mint failing.
#[tauri::command]
pub async fn fediverse_mint(
    app_state: tauri::State<'_, AppState>,
    chat_state: tauri::State<'_, ChatState>,
    handle: String,
) -> Result<String, String> {
    ensure_chat_enabled(&app_state)?;
    let client = chat_state.get().await?;
    let identity = client
        .mint_actor_identity(&handle, DEFAULT_FEDI_DOMAIN, None)
        .await
        .map_err(|e| e.to_string())?;
    if let Ok(mut s) = app_state.settings.lock() {
        s.fediverse_handle = handle;
        if let Err(e) = s.save(&app_state.settings_path) {
            tracing::warn!("minted handle held in memory only; settings save failed: {e}");
        }
    }
    Ok(identity.actor_url.to_string())
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
        .publish_public_post(&handle, None, &post)
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
}
