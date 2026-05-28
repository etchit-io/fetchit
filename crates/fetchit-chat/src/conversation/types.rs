//! Pure conversation state: types, constants, and inherent methods that
//! never touch I/O or the network.

use crate::chat_crypto::AEAD_KEY_LEN;
use crate::error::ChatError;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default auto-rekey interval (7 days in ms).
pub const DEFAULT_AUTO_REKEY_INTERVAL_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// How long a prior-key entry stays valid for in-flight envelopes
/// crossing an epoch transition.
pub const PRIOR_KEY_WINDOW_MS: u64 = 60 * 1000;

/// Conversation role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    /// Can add/remove members, trigger auto-rekey.
    Admin,
    /// Can only send messages.
    Member,
}

/// A device's participation status in a conversation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberDeviceStatus {
    /// Currently active recipient device.
    Active,
    /// Device revoked; do not address.
    Revoked,
}

fn default_active() -> MemberDeviceStatus {
    MemberDeviceStatus::Active
}

/// Per-device record inside a `Member`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberDevice {
    /// 32 bytes (hex on disk).
    pub agent_id_hex: String,
    /// ML-KEM-768 public key, base64.
    pub kem_public_key_b64: String,
    /// Epoch at which this device was added.
    pub added_at_epoch: u32,
    /// Active | Revoked.
    #[serde(default = "default_active")]
    pub status: MemberDeviceStatus,
}

/// One member (user) of a conversation, with their device list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// Opt-in. None for single-device legacy contacts.
    pub user_id_hex: Option<String>,
    /// Devices owned by this member.
    pub devices: Vec<MemberDevice>,
    /// Epoch at which this member joined.
    pub joined_at_epoch: u32,
}

/// A symmetric key from a prior epoch, kept alive for in-flight envelopes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriorKey {
    /// Epoch this key was the current key for.
    pub epoch: u32,
    /// Base64-encoded key bytes.
    pub key_b64: String,
    /// Unix-ms after which this prior key is dropped.
    pub expires_at_ms: u64,
}

/// One full conversation, serialized to disk via vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conversation {
    /// 32 random bytes assigned at creation.
    pub group_id_hex: String,
    /// Optional human-readable name (group only).
    pub name: Option<String>,
    /// Members of the conversation, including self.
    pub members: Vec<Member>,
    /// Bumps on every membership change or auto-rekey.
    pub current_epoch: u32,
    /// Current symmetric key (base64). Sensitive.
    pub current_key_b64: String,
    /// Recent prior keys for in-flight late-arriving envelopes.
    pub prior_keys: Vec<PriorKey>,
    /// What role our local device plays in this conversation.
    pub own_role: Role,
    /// Created-at, Unix ms.
    pub created_at_ms: u64,
    /// Most recent rekey at, Unix ms.
    pub last_rekey_at_ms: u64,
    /// Auto-rekey interval in ms (default 7 days).
    pub auto_rekey_interval_ms: u64,
}

impl Conversation {
    /// Build a fresh DM conversation between `self` (the local identity)
    /// and `peer_member`. Generates the `group_id` and the initial key.
    ///
    /// # Errors
    /// None today; signature kept fallible for forward compatibility.
    pub fn new_dm(
        local_member: Member,
        peer_member: Member,
        name: Option<String>,
    ) -> Result<Self, ChatError> {
        let mut group_id = [0u8; 32];
        OsRng.fill_bytes(&mut group_id);
        let key = crate::chat_crypto::random_symmetric_key(&mut OsRng);
        let now = now_ms();
        Ok(Self {
            group_id_hex: hex::encode(group_id),
            name,
            members: vec![local_member, peer_member],
            current_epoch: 0,
            current_key_b64: B64.encode(key),
            prior_keys: Vec::new(),
            own_role: Role::Admin,
            created_at_ms: now,
            last_rekey_at_ms: now,
            auto_rekey_interval_ms: DEFAULT_AUTO_REKEY_INTERVAL_MS,
        })
    }

    /// Construct from a Welcome payload (we just joined a conversation).
    #[must_use]
    pub fn from_welcome(payload: WelcomePayload) -> Self {
        let now = now_ms();
        Self {
            group_id_hex: payload.group_id_hex,
            name: payload.name,
            members: payload.members,
            current_epoch: payload.epoch,
            current_key_b64: payload.current_key_b64,
            prior_keys: Vec::new(),
            own_role: Role::Member,
            created_at_ms: now,
            last_rekey_at_ms: now,
            auto_rekey_interval_ms: DEFAULT_AUTO_REKEY_INTERVAL_MS,
        }
    }

    /// Current key as fixed-size bytes.
    ///
    /// # Errors
    /// Base64 decode failure or wrong length.
    pub fn current_key(&self) -> Result<[u8; AEAD_KEY_LEN], ChatError> {
        let v = B64
            .decode(&self.current_key_b64)
            .map_err(|e| ChatError::Invalid(format!("current_key b64: {e}")))?;
        if v.len() != AEAD_KEY_LEN {
            return Err(ChatError::Invalid("current_key length".into()));
        }
        let mut out = [0u8; AEAD_KEY_LEN];
        out.copy_from_slice(&v);
        Ok(out)
    }

    /// 32-byte raw `group_id`.
    ///
    /// # Errors
    /// Hex decode or wrong length.
    pub fn group_id_bytes(&self) -> Result<[u8; 32], ChatError> {
        let v = hex::decode(&self.group_id_hex)
            .map_err(|e| ChatError::Invalid(format!("group_id hex: {e}")))?;
        v.try_into()
            .map_err(|_| ChatError::Invalid("group_id length".into()))
    }

    /// Look up a key for `epoch`: `current_key` if epoch matches, else a
    /// non-expired `prior_keys` entry.
    ///
    /// # Errors
    /// Bad base64 in a stored prior key.
    pub fn key_for_epoch(&self, epoch: u32) -> Result<Option<[u8; AEAD_KEY_LEN]>, ChatError> {
        if epoch == self.current_epoch {
            return self.current_key().map(Some);
        }
        let now = now_ms();
        for prior in &self.prior_keys {
            if prior.epoch != epoch {
                continue;
            }
            if prior.expires_at_ms <= now {
                continue;
            }
            let bytes = B64
                .decode(&prior.key_b64)
                .map_err(|e| ChatError::Invalid(format!("prior key b64: {e}")))?;
            if bytes.len() != AEAD_KEY_LEN {
                return Err(ChatError::Invalid("prior key length".into()));
            }
            let mut k = [0u8; AEAD_KEY_LEN];
            k.copy_from_slice(&bytes);
            return Ok(Some(k));
        }
        Ok(None)
    }

    /// Drop expired prior-keys entries.
    pub fn sweep_prior_keys(&mut self) {
        let now = now_ms();
        self.prior_keys.retain(|p| p.expires_at_ms > now);
    }

    /// Bump epoch + install a new `current_key`. Pushes the old key into
    /// `prior_keys` with a 60s expiry.
    pub fn advance_epoch(&mut self, new_key: [u8; AEAD_KEY_LEN]) {
        let now = now_ms();
        self.prior_keys.push(PriorKey {
            epoch: self.current_epoch,
            key_b64: self.current_key_b64.clone(),
            expires_at_ms: now + PRIOR_KEY_WINDOW_MS,
        });
        self.current_epoch += 1;
        self.current_key_b64 = B64.encode(new_key);
        self.last_rekey_at_ms = now;
        self.sweep_prior_keys();
    }

    /// Should auto-rekey fire?
    #[must_use]
    pub fn auto_rekey_due(&self) -> bool {
        if self.own_role != Role::Admin {
            return false;
        }
        now_ms().saturating_sub(self.last_rekey_at_ms) > self.auto_rekey_interval_ms
    }

    /// Iterate every recipient device — every Active device of every
    /// member EXCLUDING the local device.
    pub fn fanout_devices<'a>(
        &'a self,
        local_agent_id_hex: &'a str,
    ) -> impl Iterator<Item = &'a MemberDevice> + 'a {
        self.members
            .iter()
            .flat_map(|m| m.devices.iter())
            .filter(move |d| {
                d.status == MemberDeviceStatus::Active && d.agent_id_hex != local_agent_id_hex
            })
    }
}

/// Inner payload of a Welcome envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WelcomePayload {
    /// Hex group id.
    pub group_id_hex: String,
    /// Base64 current key.
    pub current_key_b64: String,
    /// Epoch the carried key belongs to.
    pub epoch: u32,
    /// Full member list at the welcome epoch.
    pub members: Vec<Member>,
    /// Optional conversation name.
    pub name: Option<String>,
}

/// Inner payload of a Message envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessagePayload {
    /// Sender display name.
    pub sender_name: Option<String>,
    /// Plaintext body.
    pub body: String,
    /// Sender-asserted timestamp (mirrors envelope `timestamp_ms`).
    pub ts_ms: u64,
}

pub(super) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn local_member(agent_id_hex: &str, kem_pub_b64: &str) -> Member {
        Member {
            user_id_hex: None,
            devices: vec![MemberDevice {
                agent_id_hex: agent_id_hex.to_owned(),
                kem_public_key_b64: kem_pub_b64.to_owned(),
                added_at_epoch: 0,
                status: MemberDeviceStatus::Active,
            }],
            joined_at_epoch: 0,
        }
    }

    #[test]
    fn fanout_excludes_local_device() {
        let local_hex = "a".repeat(64);
        let conv = Conversation {
            group_id_hex: "0".repeat(64),
            name: None,
            members: vec![
                local_member(&local_hex, "AAAA"),
                local_member(&"b".repeat(64), "BBBB"),
            ],
            current_epoch: 0,
            current_key_b64: B64.encode([0u8; 32]),
            prior_keys: vec![],
            own_role: Role::Admin,
            created_at_ms: 0,
            last_rekey_at_ms: 0,
            auto_rekey_interval_ms: DEFAULT_AUTO_REKEY_INTERVAL_MS,
        };
        let fanout: Vec<&MemberDevice> = conv.fanout_devices(&local_hex).collect();
        assert_eq!(fanout.len(), 1);
        assert_eq!(fanout[0].agent_id_hex, "b".repeat(64));
    }

    #[test]
    fn prior_keys_eviction_after_window() {
        let mut conv = Conversation {
            group_id_hex: "0".repeat(64),
            name: None,
            members: vec![],
            current_epoch: 1,
            current_key_b64: B64.encode([1u8; 32]),
            prior_keys: vec![PriorKey {
                epoch: 0,
                key_b64: B64.encode([0u8; 32]),
                expires_at_ms: 1,
            }],
            own_role: Role::Admin,
            created_at_ms: 0,
            last_rekey_at_ms: 0,
            auto_rekey_interval_ms: DEFAULT_AUTO_REKEY_INTERVAL_MS,
        };
        conv.sweep_prior_keys();
        assert!(conv.prior_keys.is_empty());
    }
}
