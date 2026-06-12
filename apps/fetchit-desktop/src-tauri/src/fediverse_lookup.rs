//! M5.1 handle lookup: one search box, two outcomes. Composes the
//! resolution chain (`WebFinger`, actor doc, attestation v2 verify,
//! relay profile-index, Autonomi manifest) and returns a flat DTO the
//! actor card renders. Crypto or attestation failure means the
//! public-only card with a visible `verify_failure`; transport failure
//! after that point is a command error (honest error state, never a
//! silent trust downgrade).

use crate::chat::{ensure_chat_enabled, ChatState};
use crate::profile::{build_profile_outcome, AvatarDto, ProfileOutcome, MAX_MANIFEST_BYTES};
use crate::state::AppState;
use serde::Serialize;

/// Flat lookup result. `kind` is `"verified"` or `"publicOnly"`;
/// fields outside the matching kind are `None`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LookupDto {
    /// `"verified"` or `"publicOnly"`.
    pub kind: String,
    /// Canonical `@local@instance` form of the looked-up handle.
    pub handle: String,
    /// Actor URL the handle resolved to.
    pub actor_url: String,
    /// Derived agent id (verified only).
    pub agent_id_hex: Option<String>,
    /// Display name from the verified profile manifest, when published.
    pub display_name: Option<String>,
    /// Bio from the verified profile manifest.
    pub bio: Option<String>,
    /// Avatar metadata; bytes load lazily via `chat_fetch_avatar`.
    pub avatar: Option<AvatarDto>,
    /// Synthesized v3 share URI; "Message privately" feeds it to the
    /// existing `chat_pair_accept` flow unchanged.
    pub share_uri: Option<String>,
    /// Set when this handle previously resolved to a different agent
    /// id on this device ("handle changed hands").
    pub previous_agent_id_hex: Option<String>,
    /// Set when an attestation was present but failed verification.
    pub verify_failure: Option<String>,
}

impl LookupDto {
    fn public_only(handle: String, actor_url: String, verify_failure: Option<String>) -> Self {
        Self {
            kind: "publicOnly".into(),
            handle,
            actor_url,
            agent_id_hex: None,
            display_name: None,
            bio: None,
            avatar: None,
            share_uri: None,
            previous_agent_id_hex: None,
            verify_failure,
        }
    }
}

/// Resolve a fediverse handle to an actor card.
///
/// # Errors
/// User-facing strings for transport-class failures only; trust
/// failures return the public-only DTO instead (fail closed, visibly).
#[tauri::command]
pub async fn fediverse_lookup(
    app_state: tauri::State<'_, AppState>,
    chat_state: tauri::State<'_, ChatState>,
    handle: String,
) -> Result<LookupDto, String> {
    ensure_chat_enabled(&app_state)?;
    let parsed = fetchit_fedi::parse_mention(handle.trim()).map_err(|e| e.to_string())?;
    let canonical = format!("@{}@{}", parsed.local, parsed.instance);
    let actor_url = fetchit_fedi::resolve_handle(&parsed)
        .await
        .map_err(|e| format!("couldn't resolve {canonical} ({e})"))?;
    let actor = fetchit_fedi::lookup::fetch_remote_actor(&actor_url)
        .await
        .map_err(|e| format!("couldn't fetch that account ({e})"))?;
    let actor_url_str = actor.id.to_string();

    let Some(att) = actor.attestation_v2.clone() else {
        return Ok(LookupDto::public_only(canonical, actor_url_str, None));
    };
    let agent_id_hex = match actor.verify_attestation_v2() {
        Ok(id) => id,
        Err(e) => {
            return Ok(LookupDto::public_only(
                canonical,
                actor_url_str,
                Some(e.to_string()),
            ))
        }
    };
    // The relay hint is part of the verified binding; one that does
    // not parse fails closed to public-only, same as a bad signature.
    let Ok(relay) = att.relay_hint.parse::<url::Url>() else {
        return Ok(LookupDto::public_only(
            canonical,
            actor_url_str,
            Some("attested relay hint is not a valid URL".into()),
        ));
    };

    // Live profile-index record from THEIR relay (self-signed; the
    // fetch cross-checks the agent id binding internally).
    let http = fetchit_chat::relay_http::guarded_client();
    let record = fetchit_chat::pair::fetch_index_record_by_id(&relay, &agent_id_hex, &http)
        .await
        .map_err(|e| format!("couldn't reach their relay ({e})"))?;

    // Rich display fields from the Autonomi manifest; a missing or
    // unverifiable manifest degrades to handle-only display, never an
    // error (the index record already proved the identity binding).
    let (display_name, bio, avatar) =
        match crate::fetch_autonomi_bytes(&app_state, &record.profile_addr, MAX_MANIFEST_BYTES)
            .await
        {
            Ok(bytes) => {
                match build_profile_outcome(&agent_id_hex, &record.agent_id, &bytes, None) {
                    Ok(ProfileOutcome::Profile(dto)) => {
                        (Some(dto.display_name), dto.bio, dto.avatar)
                    }
                    _ => (None, None, None),
                }
            }
            Err(_) => (None, None, None),
        };

    let share_uri =
        fetchit_chat::profile::to_v3_share_uri(&agent_id_hex, &record.profile_addr, &relay)
            .map_err(|e| format!("couldn't build the contact pointer ({e})"))?;

    // Continuity ledger: surfaces "handle changed hands". Best-effort;
    // a REST-only client (no layout) just skips continuity.
    let client = chat_state.get().await?;
    let previous_agent_id_hex = client.layout().and_then(|layout| {
        match fetchit_chat::fedi_resolutions::note_resolution(layout, &canonical, &agent_id_hex) {
            Ok(fetchit_chat::fedi_resolutions::ResolutionChange::Changed {
                previous_agent_id_hex,
            }) => Some(previous_agent_id_hex),
            _ => None,
        }
    });

    Ok(LookupDto {
        kind: "verified".into(),
        handle: canonical,
        actor_url: actor_url_str,
        agent_id_hex: Some(agent_id_hex),
        display_name,
        bio,
        avatar,
        share_uri: Some(share_uri),
        previous_agent_id_hex,
        verify_failure: None,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn public_only_dto_serializes_with_kind_and_camel_case() {
        let dto = LookupDto::public_only(
            "@gargron@mastodon.social".into(),
            "https://mastodon.social/users/Gargron".into(),
            Some("attestation signature does not verify".into()),
        );
        let v = serde_json::to_value(&dto).unwrap();
        assert_eq!(v["kind"], "publicOnly");
        assert_eq!(v["verifyFailure"], "attestation signature does not verify");
        assert!(v["agentIdHex"].is_null());
        assert!(v["shareUri"].is_null());
        assert!(v["previousAgentIdHex"].is_null());
    }

    #[test]
    fn verified_dto_carries_bootstrap_fields() {
        let dto = LookupDto {
            kind: "verified".into(),
            handle: "@josh@etchit.io".into(),
            actor_url: "https://etchit.io/actors/josh".into(),
            agent_id_hex: Some("a".repeat(64)),
            display_name: Some("Josh".into()),
            bio: None,
            avatar: None,
            share_uri: Some(format!(
                "fetchit://share/v3/{}/{}?relay=x",
                "a".repeat(64),
                "b".repeat(64)
            )),
            previous_agent_id_hex: None,
            verify_failure: None,
        };
        let v = serde_json::to_value(&dto).unwrap();
        assert_eq!(v["kind"], "verified");
        assert!(v["shareUri"]
            .as_str()
            .unwrap()
            .starts_with("fetchit://share/v3/"));
        assert_eq!(v["displayName"], "Josh");
        assert!(v["previousAgentIdHex"].is_null());
        assert!(v["verifyFailure"].is_null());
    }
}
