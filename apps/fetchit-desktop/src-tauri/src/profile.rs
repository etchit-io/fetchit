//! Read-only profile-card commands (desktop). Resolves a contact's v3
//! profile manifest off Autonomi, verifies it, and returns a typed DTO.
//! The security-critical logic lives in pure functions tested against
//! the `fetchit-chat` fixtures; the Tauri commands are thin I/O.

use fetchit_chat::profile::{ProfileError, ProfileManifest};
use serde::{Deserialize, Serialize};

/// Outcome of a profile fetch. `none` is the honest non-error state for
/// a contact who has not published (tombstone or relay 404).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ProfileOutcome {
    Profile(ProfileDto),
    None,
}

/// The render-ready profile. Camel-cased for the TS frontend. The avatar
/// carries only metadata; bytes are fetched lazily by `chat_fetch_avatar`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileDto {
    pub display_name: String,
    pub bio: Option<String>,
    pub website: Option<String>,
    pub links: Vec<LinkDto>,
    pub avatar: Option<AvatarDto>,
    pub issued_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkDto {
    pub kind: String,
    pub label: String,
    pub addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvatarDto {
    pub addr: String,
    pub mime: String,
    pub w: u16,
    pub h: u16,
    pub bytes_len: u32,
}

/// Verify a fetched manifest and bind it to the expected identity.
///
/// `requested` is the agent id the user asked for; `index_agent_id` is
/// the agent id the relay index returned (already cross-checked == the
/// request upstream). `watermark` is the last-seen `issued_at_ms` for
/// downgrade defense. On success returns the render-ready DTO; on any
/// verification failure returns a short, honest, user-facing message.
///
/// # Errors
/// Returns a user-facing string when the manifest is malformed, fails
/// verification, is stale, or belongs to a different identity.
pub fn build_profile_outcome(
    requested: &str,
    index_agent_id: &str,
    manifest_bytes: &[u8],
    watermark: Option<u64>,
) -> Result<ProfileOutcome, String> {
    let json = std::str::from_utf8(manifest_bytes)
        .map_err(|_| "profile manifest is not valid UTF-8".to_string())?;
    let manifest = ProfileManifest::parse(json).map_err(map_profile_err)?;
    manifest.verify(watermark).map_err(map_profile_err)?;
    if manifest.agent_id != requested || index_agent_id != requested {
        return Err("this profile belongs to a different identity".to_string());
    }
    Ok(ProfileOutcome::Profile(ProfileDto {
        display_name: manifest.display_name,
        bio: manifest.bio,
        website: manifest.website,
        links: manifest
            .links
            .into_iter()
            .map(|l| LinkDto {
                kind: l.kind,
                label: l.label,
                addr: l.addr,
            })
            .collect(),
        avatar: manifest.avatar.map(|a| AvatarDto {
            addr: a.addr,
            mime: a.mime,
            w: a.w,
            h: a.h,
            bytes_len: a.bytes_len,
        }),
        issued_at_ms: manifest.issued_at_ms,
    }))
}

fn map_profile_err(e: ProfileError) -> String {
    match e {
        ProfileError::Stale { .. } => "a stale copy of this profile was rejected".to_string(),
        ProfileError::SigVerifyFailed | ProfileError::AgentIdMismatch { .. } => {
            "this profile failed verification".to_string()
        }
        other => format!("this profile could not be read ({other})"),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    const FIXTURES: &str = "../../../tests/fixtures/profile-manifest-v1";

    fn manifest_bytes(dir: &str) -> Vec<u8> {
        std::fs::read(format!("{FIXTURES}/{dir}/manifest.json")).unwrap()
    }
    fn manifest_agent_id(dir: &str) -> String {
        let m = ProfileManifest::parse(&String::from_utf8(manifest_bytes(dir)).unwrap()).unwrap();
        m.agent_id
    }

    #[test]
    fn maximal_builds_dto() {
        let aid = manifest_agent_id("maximal");
        let out = build_profile_outcome(&aid, &aid, &manifest_bytes("maximal"), None).unwrap();
        let ProfileOutcome::Profile(dto) = out else {
            panic!("expected profile")
        };
        assert!(!dto.display_name.is_empty());
        assert!(dto.avatar.is_some());
        assert!(!dto.links.is_empty());
    }

    #[test]
    fn tampered_manifest_rejected() {
        let aid = manifest_agent_id("maximal");
        assert!(
            build_profile_outcome(&aid, &aid, &manifest_bytes("tampered-maximal"), None).is_err()
        );
    }

    #[test]
    fn manifest_for_other_identity_rejected() {
        let wrong = "ff".repeat(32);
        assert!(build_profile_outcome(&wrong, &wrong, &manifest_bytes("maximal"), None).is_err());
    }

    #[test]
    fn stale_manifest_below_watermark_rejected() {
        let aid = manifest_agent_id("maximal");
        assert!(
            build_profile_outcome(&aid, &aid, &manifest_bytes("maximal"), Some(u64::MAX)).is_err()
        );
    }

    #[test]
    fn minimal_builds_dto_without_avatar() {
        let aid = manifest_agent_id("minimal");
        let out = build_profile_outcome(&aid, &aid, &manifest_bytes("minimal"), None).unwrap();
        let ProfileOutcome::Profile(dto) = out else {
            panic!()
        };
        assert!(dto.avatar.is_none());
    }
}
