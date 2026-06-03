//! Pure conversation state: types, constants, and inherent methods that
//! never touch I/O or the network.

use crate::chat_crypto::AEAD_KEY_LEN;
use crate::error::ChatError;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
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

/// Conversation trust posture from the local user's perspective.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TrustState {
    /// Newly installed via TOFU welcome from a previously-unknown
    /// sender. Messages flow but the UI surfaces this as untrusted
    /// until the user accepts the contact request.
    #[default]
    Pending,
    /// The local user has accepted the contact.
    Confirmed,
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
    /// ML-DSA-65 public key (base64). Populated for v2 cards; older
    /// `MemberDevice` records may have `None` and require TOFU
    /// resolution against the sender-bound `agent_id`.
    #[serde(default)]
    pub agent_public_key_b64: Option<String>,
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
    /// Trust posture for first-contact TOFU welcomes. Defaults to
    /// `Pending` so persisted-pre-this-change conversations come back
    /// untrusted and require explicit confirmation.
    #[serde(default)]
    pub trust_state: TrustState,
    /// Replay-protection window: most recent 64 distinct nonces per
    /// sender. Bounded LRU keyed by hex-encoded `sender_agent_id`; on
    /// the 65th distinct nonce the oldest entry is evicted. Persists
    /// across restarts so a process-bounce can't reset the window.
    /// On upgrade from a pre-window disk image, the field deserialises
    /// empty and the first 64 inbounds per sender are not replay-protected;
    /// acceptable for the M0 deployment shape.
    #[serde(default)]
    pub seen_nonces: BTreeMap<String, VecDeque<[u8; 12]>>,
    /// Local history cache for `MlsEncrypted` groups — x0xd's `/messages`
    /// returns an error for those, so the client persists here. Cap
    /// at 1000 entries (oldest evicted) per
    /// `private/m2-decisions.md` Decision 2. `#[serde(default)]` for
    /// backward compat with pre-M2 vault files.
    #[serde(default)]
    pub history: VecDeque<HistoryEntry>,
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
            // The local user initiated the conversation, so it is
            // trusted by construction.
            trust_state: TrustState::Confirmed,
            seen_nonces: BTreeMap::new(),
            history: VecDeque::new(),
        })
    }

    /// Construct from a Welcome payload (we just joined a conversation).
    ///
    /// `trust_state` is supplied by the caller: dispatching an
    /// unsolicited welcome from an unknown sender installs `Pending`;
    /// a welcome from a contact already on file installs `Confirmed`.
    #[must_use]
    pub fn from_welcome(payload: WelcomePayload, trust_state: TrustState) -> Self {
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
            trust_state,
            seen_nonces: BTreeMap::new(),
            history: VecDeque::new(),
        }
    }

    /// Flip `TrustState::Pending` to `TrustState::Confirmed`.
    /// No-op for already-Confirmed conversations. The caller is
    /// responsible for persisting via `ConversationRegistry::save`.
    pub fn confirm_trust(&mut self) {
        if self.trust_state == TrustState::Pending {
            self.trust_state = TrustState::Confirmed;
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

    /// Maximum entries kept in `history` before the oldest is evicted.
    pub const HISTORY_CAP: usize = 1000;

    /// Append a history entry, evicting the oldest if at capacity.
    /// Use in the receive path after a successful decrypt.
    pub fn push_history(&mut self, entry: HistoryEntry) {
        if self.history.len() >= Self::HISTORY_CAP {
            self.history.pop_front();
        }
        self.history.push_back(entry);
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

    /// Check if `nonce` was recently observed from `sender_agent_hex`,
    /// and record it as seen if not. Returns `true` when the nonce is
    /// a replay (caller must drop without processing), `false` when it
    /// is fresh (caller continues).
    ///
    /// Maintains a 64-entry per-sender LRU: on the 65th distinct nonce
    /// the oldest is evicted.
    #[must_use]
    pub fn check_and_record_nonce(&mut self, sender_agent_hex: &str, nonce: [u8; 12]) -> bool {
        /// Spec §7: 64-message sliding window keyed by `(sender, nonce)`.
        const WINDOW_SIZE: usize = 64;
        // Replay fast-path: borrow-only lookup avoids the String alloc
        // that BTreeMap::entry would force on every inbound.
        if let Some(window) = self.seen_nonces.get(sender_agent_hex) {
            if window.contains(&nonce) {
                return true;
            }
        }
        let entry = self
            .seen_nonces
            .entry(sender_agent_hex.to_owned())
            .or_default();
        if entry.len() >= WINDOW_SIZE {
            entry.pop_front();
        }
        entry.push_back(nonce);
        false
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
    /// Logical message identifier (hex). Same value on every fanout
    /// envelope of one logical send, so a receiver always echoes the
    /// same `message_id` in its `DeliveryReceipt`. Older payloads may
    /// be missing this field — fall back to `None` and skip the
    /// receipt path in that case.
    #[serde(default)]
    pub message_id: Option<String>,
}

/// Inner payload of a `DeliveryReceipt` envelope.
///
/// The recipient of a `Message` envelope emits a `DeliveryReceipt` back to the
/// original sender once the message has been decrypted. `message_id` echoes
/// the relay's `dedupe_key` (hex-encoded) of the original message envelope so
/// the sender can correlate the receipt to a specific outbound message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryReceiptPayload {
    /// Hex-encoded dedupe key of the original message envelope.
    pub message_id: String,
    /// Recipient-asserted decode timestamp, milliseconds since the Unix epoch.
    pub received_at_ms: u64,
}

/// One persisted message in a private-secure group's local history.
/// Plaintext at rest is acceptable because the vault file is AEAD-
/// sealed under the FCV1 master key per `at_rest.rs`. x0xd refuses
/// `GET /messages` for `MlsEncrypted` groups, so the client is the
/// source of truth for the user's group transcript.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Hex sender agent id.
    pub sender_agent_id_hex: String,
    /// Optional display name from the sender at send time.
    pub sender_name: Option<String>,
    /// Plaintext body.
    pub body: String,
    /// Sender-asserted Unix-ms timestamp (mirrors envelope `timestamp_ms`).
    pub ts_ms: u64,
    /// Logical message id (hex). Same value future delivery-receipts
    /// will echo back.
    pub message_id: String,
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
                agent_public_key_b64: None,
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
            trust_state: TrustState::Confirmed,
            seen_nonces: BTreeMap::new(),
            history: VecDeque::new(),
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
            trust_state: TrustState::Confirmed,
            seen_nonces: BTreeMap::new(),
            history: VecDeque::new(),
        };
        conv.sweep_prior_keys();
        assert!(conv.prior_keys.is_empty());
    }

    #[test]
    fn auto_rekey_due_fires_when_interval_elapsed() {
        let conv = Conversation {
            group_id_hex: "0".repeat(64),
            name: None,
            members: vec![],
            current_epoch: 0,
            current_key_b64: B64.encode([1u8; 32]),
            prior_keys: vec![],
            own_role: Role::Admin,
            created_at_ms: 0,
            last_rekey_at_ms: 0,
            auto_rekey_interval_ms: 1,
            trust_state: TrustState::Confirmed,
            seen_nonces: BTreeMap::new(),
            history: VecDeque::new(),
        };
        assert!(conv.auto_rekey_due());
    }

    #[test]
    fn auto_rekey_due_does_not_fire_for_member_role() {
        let conv = Conversation {
            group_id_hex: "0".repeat(64),
            name: None,
            members: vec![],
            current_epoch: 0,
            current_key_b64: B64.encode([1u8; 32]),
            prior_keys: vec![],
            own_role: Role::Member,
            created_at_ms: 0,
            last_rekey_at_ms: 0,
            auto_rekey_interval_ms: 1,
            trust_state: TrustState::Confirmed,
            seen_nonces: BTreeMap::new(),
            history: VecDeque::new(),
        };
        assert!(!conv.auto_rekey_due(), "Member role must not auto-rekey");
    }

    #[test]
    fn advance_epoch_after_auto_rekey_due_resets_timer() {
        let mut conv = Conversation {
            group_id_hex: "0".repeat(64),
            name: None,
            members: vec![],
            current_epoch: 0,
            current_key_b64: B64.encode([1u8; 32]),
            prior_keys: vec![],
            own_role: Role::Admin,
            created_at_ms: 0,
            last_rekey_at_ms: 0,
            auto_rekey_interval_ms: 1,
            trust_state: TrustState::Confirmed,
            seen_nonces: BTreeMap::new(),
            history: VecDeque::new(),
        };
        assert!(conv.auto_rekey_due());
        conv.advance_epoch([2u8; 32]);
        assert_eq!(conv.current_epoch, 1);
        assert_eq!(conv.prior_keys.len(), 1);
        assert!(
            !conv.auto_rekey_due(),
            "advance_epoch should reset last_rekey_at_ms to now"
        );
    }

    #[test]
    fn check_and_record_nonce_returns_true_on_replay() {
        let mut conv = Conversation {
            group_id_hex: "0".repeat(64),
            name: None,
            members: vec![],
            current_epoch: 0,
            current_key_b64: B64.encode([1u8; 32]),
            prior_keys: vec![],
            own_role: Role::Admin,
            created_at_ms: 0,
            last_rekey_at_ms: 0,
            auto_rekey_interval_ms: DEFAULT_AUTO_REKEY_INTERVAL_MS,
            trust_state: TrustState::Confirmed,
            seen_nonces: BTreeMap::new(),
            history: VecDeque::new(),
        };
        let nonce = [0xAB; 12];
        assert!(!conv.check_and_record_nonce("alice", nonce));
        assert!(
            conv.check_and_record_nonce("alice", nonce),
            "second observation of the same nonce must be flagged as replay",
        );
        assert!(
            !conv.check_and_record_nonce("alice", [0xCD; 12]),
            "different nonce same sender is fresh",
        );
        assert!(
            !conv.check_and_record_nonce("bob", nonce),
            "different sender same nonce is fresh — keying is per-sender",
        );
    }

    #[test]
    fn check_and_record_nonce_evicts_oldest_at_65th() {
        let mut conv = Conversation {
            group_id_hex: "0".repeat(64),
            name: None,
            members: vec![],
            current_epoch: 0,
            current_key_b64: B64.encode([1u8; 32]),
            prior_keys: vec![],
            own_role: Role::Admin,
            created_at_ms: 0,
            last_rekey_at_ms: 0,
            auto_rekey_interval_ms: DEFAULT_AUTO_REKEY_INTERVAL_MS,
            trust_state: TrustState::Confirmed,
            seen_nonces: BTreeMap::new(),
            history: VecDeque::new(),
        };
        for i in 0..64u8 {
            assert!(!conv.check_and_record_nonce("alice", [i; 12]));
        }
        // Window is now [0..63]; replay of any one is detected.
        assert!(conv.check_and_record_nonce("alice", [0; 12]));
        // 65th distinct nonce — evicts [0; 12] (the oldest).
        assert!(!conv.check_and_record_nonce("alice", [0xFF; 12]));
        // [0; 12] should now be re-acceptable (was evicted).
        assert!(!conv.check_and_record_nonce("alice", [0; 12]));
        // [2; 12] is still in the window (only [0] and [1] have been
        // evicted by the two extra inserts).
        assert!(conv.check_and_record_nonce("alice", [2; 12]));
    }

    #[test]
    fn check_and_record_nonce_windows_are_independent_per_sender() {
        let mut conv = Conversation {
            group_id_hex: "0".repeat(64),
            name: None,
            members: vec![],
            current_epoch: 0,
            current_key_b64: B64.encode([1u8; 32]),
            prior_keys: vec![],
            own_role: Role::Admin,
            created_at_ms: 0,
            last_rekey_at_ms: 0,
            auto_rekey_interval_ms: DEFAULT_AUTO_REKEY_INTERVAL_MS,
            trust_state: TrustState::Confirmed,
            seen_nonces: BTreeMap::new(),
            history: VecDeque::new(),
        };
        // Fill Alice's window completely.
        for i in 0..64u8 {
            assert!(!conv.check_and_record_nonce("alice", [i; 12]));
        }
        // Bob can still record [0; 12] — independent window.
        assert!(!conv.check_and_record_nonce("bob", [0; 12]));
        // Evicting Alice's oldest doesn't touch Bob's.
        assert!(!conv.check_and_record_nonce("alice", [0xFF; 12]));
        // Bob's [0; 12] is still recorded (replays).
        assert!(conv.check_and_record_nonce("bob", [0; 12]));
    }

    #[test]
    fn conversation_without_seen_nonces_field_deserializes() {
        // Backward-compat: pre-replay-window conversations on disk
        // don't carry `seen_nonces`. They must still load — the
        // serde(default) gives them an empty window.
        let json = serde_json::json!({
            "group_id_hex": "0".repeat(64),
            "name": null,
            "members": [],
            "current_epoch": 0,
            "current_key_b64": B64.encode([1u8; 32]),
            "prior_keys": [],
            "own_role": "Admin",
            "created_at_ms": 0,
            "last_rekey_at_ms": 0,
            "auto_rekey_interval_ms": DEFAULT_AUTO_REKEY_INTERVAL_MS,
            "trust_state": "Confirmed",
        });
        let conv: Conversation = serde_json::from_value(json).unwrap();
        assert!(conv.seen_nonces.is_empty());
    }

    #[test]
    fn confirm_trust_flips_pending_to_confirmed() {
        let mut conv = Conversation {
            group_id_hex: "0".repeat(64),
            name: None,
            members: vec![],
            current_epoch: 0,
            current_key_b64: B64.encode([1u8; 32]),
            prior_keys: vec![],
            own_role: Role::Member,
            created_at_ms: 0,
            last_rekey_at_ms: 0,
            auto_rekey_interval_ms: DEFAULT_AUTO_REKEY_INTERVAL_MS,
            trust_state: TrustState::Pending,
            seen_nonces: BTreeMap::new(),
            history: VecDeque::new(),
        };
        conv.confirm_trust();
        assert_eq!(conv.trust_state, TrustState::Confirmed);
        // Idempotent: a second call leaves it Confirmed.
        conv.confirm_trust();
        assert_eq!(conv.trust_state, TrustState::Confirmed);
    }

    fn make_minimal_conversation_for_history_test() -> Conversation {
        Conversation {
            group_id_hex: "0".repeat(64),
            name: None,
            members: vec![],
            current_epoch: 0,
            current_key_b64: B64.encode([1u8; 32]),
            prior_keys: vec![],
            own_role: Role::Admin,
            created_at_ms: 0,
            last_rekey_at_ms: 0,
            auto_rekey_interval_ms: DEFAULT_AUTO_REKEY_INTERVAL_MS,
            trust_state: TrustState::Confirmed,
            seen_nonces: BTreeMap::new(),
            history: VecDeque::new(),
        }
    }

    #[test]
    fn push_history_caps_at_thousand_entries() {
        let mut conv = make_minimal_conversation_for_history_test();
        for i in 0..1001u64 {
            conv.push_history(HistoryEntry {
                sender_agent_id_hex: "a".repeat(64),
                sender_name: None,
                body: format!("m{i}"),
                ts_ms: i,
                message_id: format!("id{i}"),
            });
        }
        assert_eq!(conv.history.len(), Conversation::HISTORY_CAP);
        assert_eq!(conv.history.front().unwrap().body, "m1");
        assert_eq!(conv.history.back().unwrap().body, "m1000");
    }

    #[test]
    fn conversation_without_history_field_deserializes_to_empty() {
        let json = serde_json::json!({
            "group_id_hex": "0".repeat(64),
            "name": null,
            "members": [],
            "current_epoch": 0,
            "current_key_b64": B64.encode([1u8; 32]),
            "prior_keys": [],
            "own_role": "Admin",
            "created_at_ms": 0,
            "last_rekey_at_ms": 0,
            "auto_rekey_interval_ms": DEFAULT_AUTO_REKEY_INTERVAL_MS,
            "trust_state": "Confirmed",
        });
        let conv: Conversation = serde_json::from_value(json).unwrap();
        assert!(conv.history.is_empty());
    }
}
