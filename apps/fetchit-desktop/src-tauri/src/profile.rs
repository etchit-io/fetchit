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

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use std::collections::BTreeMap;
use std::path::Path;

const WATERMARK_FILE: &str = "profile_fetch_watermark.json";

/// Hard ceiling on avatar bytes regardless of the manifest's declared
/// length. The manifest caps the avatar at 256x256 webp; 512 KiB is
/// comfortably above any honest encoding and well below a `DoS`.
const MAX_AVATAR_BYTES: usize = 512 * 1024;

const RASTER_MIMES: &[&str] = &["image/jpeg", "image/png", "image/webp", "image/gif"];

fn watermark_path(chat_root: &Path) -> std::path::PathBuf {
    chat_root.join(WATERMARK_FILE)
}

/// Last-seen `issued_at_ms` for a contact, or None on first view. Plain
/// JSON map at rest (non-secret monotonic timestamps).
pub fn load_watermark(chat_root: &Path, agent_id: &str) -> Option<u64> {
    let raw = std::fs::read(watermark_path(chat_root)).ok()?;
    let map: BTreeMap<String, u64> = serde_json::from_slice(&raw).ok()?;
    map.get(agent_id).copied()
}

/// Persist `issued_at_ms` for `agent_id` when it is newer than the
/// stored value (monotonic). Best-effort: a write error is non-fatal
/// (the downgrade check already ran against the loaded value).
///
/// # Errors
/// Propagates a filesystem write error.
pub fn save_watermark(chat_root: &Path, agent_id: &str, issued_at_ms: u64) -> std::io::Result<()> {
    let path = watermark_path(chat_root);
    let mut map: BTreeMap<String, u64> = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let entry = map.entry(agent_id.to_string()).or_insert(0);
    if issued_at_ms > *entry {
        *entry = issued_at_ms;
    }
    let bytes = serde_json::to_vec(&map).unwrap_or_default();
    std::fs::write(&path, bytes)
}

/// Identify a raster image purely from its leading magic bytes. Returns
/// the canonical MIME, or None for anything not an allowed raster format
/// (SVG, HTML, etc. fall through to None).
fn sniff_raster_mime(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() >= 3 && bytes[0] == 0xff && bytes[1] == 0xd8 && bytes[2] == 0xff {
        return Some("image/jpeg");
    }
    if bytes.len() >= 8 && bytes[0..8] == [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] {
        return Some("image/png");
    }
    if bytes.len() >= 6
        && &bytes[0..4] == b"GIF8"
        && (bytes[4] == 0x37 || bytes[4] == 0x39)
        && bytes[5] == 0x61
    {
        return Some("image/gif");
    }
    if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    None
}

/// Validate fetched avatar bytes and return a `data:` URL. Rejects bytes
/// over the declared length or the hard cap, and rejects bytes whose
/// magic-byte type is not the declared raster image (never trust the
/// manifest's mime string alone). The returned URL uses the SNIFFED mime
/// so the browser decodes the bytes as that raster format.
///
/// # Errors
/// Returns a user-facing string when the bytes are oversize, the declared
/// mime is not an allowed raster type, or the bytes do not match it.
pub fn validate_avatar_to_data_url(
    bytes: &[u8],
    declared_mime: &str,
    declared_bytes_len: u32,
) -> Result<String, String> {
    if bytes.len() > MAX_AVATAR_BYTES || bytes.len() as u64 > u64::from(declared_bytes_len) {
        return Err("avatar image is larger than declared".to_string());
    }
    if !RASTER_MIMES.contains(&declared_mime) {
        return Err("avatar mime is not an allowed raster image".to_string());
    }
    let sniffed = sniff_raster_mime(bytes);
    if sniffed != Some(declared_mime) {
        return Err("avatar bytes do not match the declared image type".to_string());
    }
    Ok(format!("data:{declared_mime};base64,{}", B64.encode(bytes)))
}

/// Hard ceiling on a fetched profile manifest. The v3 manifest is small
/// JSON; 64 KiB is well above any honest encoding and below a `DoS`.
const MAX_MANIFEST_BYTES: usize = 64 * 1024;

/// Hard ceiling on fetched avatar bytes. Matches `MAX_AVATAR_BYTES`; the
/// per-byte declared-length check in `validate_avatar_to_data_url` tightens
/// it further.
const MAX_AVATAR_FETCH_BYTES: usize = 512 * 1024;

/// Resolve a contact's published profile: look up their profile-index
/// record on the relay, fetch + verify the manifest off Autonomi, and
/// return a render-ready DTO. A tombstone or relay 404 is the honest
/// non-error [`ProfileOutcome::None`] (the contact hasn't published).
///
/// # Errors
/// Returns a user-facing string when the relay is unreachable, the
/// network fetch fails, or the manifest fails verification.
#[tauri::command]
pub async fn chat_fetch_profile(
    app_state: tauri::State<'_, crate::AppState>,
    state: tauri::State<'_, crate::chat::ChatState>,
    agent_id: String,
) -> Result<ProfileOutcome, String> {
    crate::chat::ensure_chat_enabled(&app_state)?;
    let relay = state.relay_url();
    let http = reqwest::Client::new();
    let record = match fetchit_chat::pair::fetch_index_record_by_id(&relay, &agent_id, &http).await
    {
        Ok(r) => r,
        Err(
            fetchit_chat::pair::PairError::Tombstoned
            | fetchit_chat::pair::PairError::RelayStatus(404),
        ) => return Ok(ProfileOutcome::None),
        Err(e) => return Err(format!("couldn't reach the profile index ({e})")),
    };
    let bytes = crate::fetch_autonomi_bytes(&app_state, &record.profile_addr, MAX_MANIFEST_BYTES)
        .await
        .map_err(|e| format!("couldn't reach the network ({e})"))?;
    let chat_root = state.store_root();
    let watermark = load_watermark(&chat_root, &agent_id);
    let outcome = build_profile_outcome(&agent_id, &record.agent_id, &bytes, watermark)?;
    if let ProfileOutcome::Profile(ref dto) = outcome {
        let _ = save_watermark(&chat_root, &agent_id, dto.issued_at_ms);
    }
    Ok(outcome)
}

/// Fetch and validate an avatar referenced by a verified profile,
/// returning a `data:` URL. The bytes are size-capped and magic-byte
/// checked against the declared mime before encoding.
///
/// # Errors
/// Returns a user-facing string when the fetch fails or the bytes fail
/// avatar validation.
#[tauri::command]
pub async fn chat_fetch_avatar(
    app_state: tauri::State<'_, crate::AppState>,
    addr: String,
    mime: String,
    bytes_len: u32,
) -> Result<String, String> {
    let bytes = crate::fetch_autonomi_bytes(&app_state, &addr, MAX_AVATAR_FETCH_BYTES)
        .await
        .map_err(|e| format!("couldn't load the avatar ({e})"))?;
    validate_avatar_to_data_url(&bytes, &mime, bytes_len)
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

    #[test]
    fn watermark_roundtrip_and_monotonic() {
        let tmp = std::env::temp_dir().join(format!("pw-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let aid = "aa".repeat(32);
        assert_eq!(load_watermark(&tmp, &aid), None);
        save_watermark(&tmp, &aid, 100).unwrap();
        assert_eq!(load_watermark(&tmp, &aid), Some(100));
        save_watermark(&tmp, &aid, 50).unwrap(); // older never lowers
        assert_eq!(load_watermark(&tmp, &aid), Some(100));
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn avatar_valid_webp_returns_data_url() {
        let mut bytes = vec![0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0, 0x57, 0x45, 0x42, 0x50];
        bytes.extend_from_slice(&[0u8; 20]);
        let len = u32::try_from(bytes.len()).unwrap();
        let url = validate_avatar_to_data_url(&bytes, "image/webp", len).unwrap();
        assert!(url.starts_with("data:image/webp;base64,"));
    }

    #[test]
    fn avatar_oversize_rejected() {
        let bytes = vec![0u8; 600 * 1024];
        let len = u32::try_from(bytes.len()).unwrap();
        assert!(validate_avatar_to_data_url(&bytes, "image/webp", len).is_err());
    }

    #[test]
    fn avatar_non_raster_bytes_rejected() {
        let bytes = b"<svg xmlns='...'/>".to_vec();
        let len = u32::try_from(bytes.len()).unwrap();
        assert!(validate_avatar_to_data_url(&bytes, "image/webp", len).is_err());
    }

    #[test]
    fn avatar_over_declared_len_rejected() {
        let mut bytes = vec![0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0, 0x57, 0x45, 0x42, 0x50];
        bytes.extend_from_slice(&[0u8; 100]);
        assert!(validate_avatar_to_data_url(&bytes, "image/webp", 10).is_err());
    }
}
