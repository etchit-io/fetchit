//! Pure conversation state: types, constants, and inherent methods that
//! never touch I/O or the network.

use super::seq_gap::{SenderSeqState, SeqObservation};
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
    /// Local history cache for DM and private-group conversations —
    /// x0xd's `/messages` returns an error for MLS-encrypted groups,
    /// so the client persists here. Cap at 1000 entries (oldest
    /// evicted) per `private/m2-decisions.md` Decision 2.
    /// `#[serde(default)]` for backward compat with pre-M2 vault files.
    #[serde(default)]
    pub history: VecDeque<HistoryEntry>,
    /// Last per-group send counter this device sealed into an outbound
    /// private-group frame (the next send uses `+1`). Zero on
    /// conversations that have never counted a send. `#[serde(default)]`
    /// for pre-gap-detection vault files.
    #[serde(default)]
    pub own_group_send_seq: u64,
    /// Receive-side per-sender sequence ledgers for missed-message
    /// detection, keyed like `seen_nonces` by hex `sender_agent_id`.
    /// `#[serde(default)]` for pre-gap-detection vault files.
    #[serde(default)]
    pub group_seq_windows: BTreeMap<String, SenderSeqState>,
    /// Wedge-watchdog: Unix-ms of the last successful inbound decrypt
    /// (message or receipt) for this conversation — "progress" in
    /// [`crate::groups::epoch_recovery::WedgeSignals`] terms. Zero on
    /// conversations that predate the watchdog (`#[serde(default)]`).
    ///
    /// Note that zero does NOT read as "never observed": it makes
    /// `stalled_for` equal `now_ms`, which exceeds any threshold. What
    /// actually holds the trip back on a freshly-upgraded vault is the
    /// separate `wedge_last_inbound_ms > wedge_last_progress_ms` gate,
    /// so the first UNDECRYPTABLE frame after upgrade can trip with no
    /// observation window. That is the intended bias — an inbound frame
    /// that will not open is the wedge signature regardless of how long
    /// we have been watching — but it is a trip, not a grace period.
    #[serde(default)]
    pub wedge_last_progress_ms: u64,
    /// Wedge-watchdog: Unix-ms of the last inbound frame ADDRESSED to
    /// this conversation regardless of decrypt outcome. A frame that
    /// fails with a stale epoch still proves the peer is live on the
    /// transport — inbound-newer-than-progress is the wedge signature
    /// (the old "receipts flowing but chat dead").
    #[serde(default)]
    pub wedge_last_inbound_ms: u64,
    /// Wedge-watchdog: our epoch at the last progress point. An epoch
    /// advance since then is itself progress and vetoes the trip.
    #[serde(default)]
    pub wedge_progress_epoch: u32,
    /// Highest epoch observed on an UNDECRYPTABLE inbound frame — what
    /// the peer is currently sealing at. A forced re-key must advance
    /// PAST this (not merely `current + 1`): at an epoch tie the peer
    /// ignores our Welcome (`<=` its epoch) and healing would take a
    /// second damped cycle.
    #[serde(default)]
    pub wedge_max_stale_epoch: u32,
    /// Read high-water mark: the newest [`HistoryEntry::ts_ms`] the user
    /// has actually had this conversation open on. Inbound messages
    /// stamped above it are what the conversation row badges as unread.
    ///
    /// Sealed in the same vault file as [`Self::history`], so the mark
    /// can never outlive — or be outlived by — the messages it covers.
    /// `#[serde(default)]` leaves a vault sealed before read marks at
    /// zero, which reads as "never opened": everything already on disk
    /// comes back unread rather than silently pre-read.
    #[serde(default)]
    pub read_ms: u64,
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
            own_group_send_seq: 0,
            group_seq_windows: BTreeMap::new(),
            wedge_last_progress_ms: 0,
            wedge_last_inbound_ms: 0,
            wedge_progress_epoch: 0,
            wedge_max_stale_epoch: 0,
            read_ms: 0,
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
            own_group_send_seq: 0,
            group_seq_windows: BTreeMap::new(),
            wedge_last_progress_ms: 0,
            wedge_last_inbound_ms: 0,
            wedge_progress_epoch: 0,
            wedge_max_stale_epoch: 0,
            read_ms: 0,
        }
    }

    /// Record an inbound per-sender group counter and classify it
    /// (first / consecutive / gap / filled hole / duplicate). Keyed
    /// like the replay window by hex `sender_agent_id`. The caller is
    /// responsible for persisting via the registry, in the same locked
    /// mutation as the dedup check.
    pub fn record_group_seq(
        &mut self,
        sender_agent_id_hex: &str,
        seq: u64,
        now_ms: u64,
    ) -> SeqObservation {
        self.group_seq_windows
            .entry(sender_agent_id_hex.to_owned())
            .or_default()
            .record(seq, now_ms)
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

    /// Messages from anyone but this device stamped after the last time
    /// the conversation was opened — the count its row badges. Saturates
    /// at [`u32::MAX`].
    ///
    /// `local_agent_id_hex` is the same discriminator
    /// [`crate::conversation::HistoryEntry::sender_agent_id_hex`] is read
    /// against everywhere else, so a message that renders as an outbound
    /// bubble can never also be counted unread — including a group send,
    /// which this device persists into its own history.
    ///
    /// A conversation that has never been opened counts its whole inbound
    /// history: messages that landed while the app was closed are exactly
    /// what the badge exists to announce.
    #[must_use]
    pub fn unread(&self, local_agent_id_hex: &str) -> u32 {
        let n = self
            .history
            .iter()
            .filter(|e| e.sender_agent_id_hex != local_agent_id_hex && e.ts_ms > self.read_ms)
            .count();
        u32::try_from(n).unwrap_or(u32::MAX)
    }

    /// Mark every message currently in `history` read. Returns `true`
    /// when the mark moved, so a caller can skip re-sealing the vault on
    /// a re-open that changed nothing. A conversation with no messages
    /// stores no mark.
    ///
    /// The mark is the HIGHEST stamp in history, not the last-arrived
    /// one: relay store-and-forward replays out of order, and the thread
    /// screen renders everything it holds sorted by stamp. Marking only
    /// up to the last arrival would leave a newer, already-displayed
    /// message badged forever.
    pub fn mark_read(&mut self) -> bool {
        let Some(newest) = self.history.iter().map(|e| e.ts_ms).max() else {
            return false;
        };
        if newest <= self.read_ms {
            return false;
        }
        self.read_ms = newest;
        true
    }

    /// Mark the history entry whose `message_id` a delivery receipt
    /// echoed as delivered. Scans newest-first (receipts arrive for
    /// recent sends). Returns `true` when an entry was newly marked;
    /// `false` when nothing matched (entry evicted past
    /// [`Self::HISTORY_CAP`], an id this side never recorded, or a
    /// duplicate receipt) so callers can skip a redundant persist.
    pub fn apply_delivery_receipt(&mut self, message_id: &str, received_at_ms: u64) -> bool {
        for entry in self.history.iter_mut().rev() {
            if entry.message_id == message_id {
                if entry.delivered_at_ms.is_some() {
                    return false;
                }
                entry.delivered_at_ms = Some(received_at_ms);
                return true;
            }
        }
        false
    }

    /// Bump epoch + install a new `current_key`. Pushes the old key into
    /// `prior_keys` with a 60s expiry.
    pub fn advance_epoch(&mut self, new_key: [u8; AEAD_KEY_LEN]) {
        self.advance_epoch_to(self.current_epoch, new_key);
    }

    /// Advance to `floor + 1` (or the normal next epoch, whichever is
    /// higher), installing `new_key`.
    ///
    /// The outgoing key is ALWAYS archived under the epoch it actually
    /// served — never under `floor`. Setting `current_epoch = floor`
    /// before calling [`Self::advance_epoch`] would file the live key
    /// under the peer's epoch instead of its own, which loses every
    /// in-flight frame at our real epoch AND makes a genuine frame at
    /// `floor` open with the wrong key — reporting `AeadOpenFailed`,
    /// the exact corruption signature the wedge ladder exists to cure.
    ///
    /// Saturating throughout: `floor` is derived from a peer-supplied
    /// epoch, and a wrap to 0 would strand the conversation below every
    /// future Welcome (`<=` is ignored) forever.
    pub fn advance_epoch_to(&mut self, floor: u32, new_key: [u8; AEAD_KEY_LEN]) {
        let now = now_ms();
        self.prior_keys.push(PriorKey {
            epoch: self.current_epoch,
            key_b64: self.current_key_b64.clone(),
            expires_at_ms: now + PRIOR_KEY_WINDOW_MS,
        });
        self.current_epoch = floor.max(self.current_epoch).saturating_add(1);
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

/// Magic prefix marking a private-group plaintext that carries a
/// structured [`GroupBodyV1`] payload (sender display name + body)
/// instead of a bare UTF-8 body. The leading NUL guarantees no
/// collision with a human-typed message: chat bodies are never sent
/// with a leading NUL byte. Legacy senders emit the bare body, which
/// [`decode_group_plaintext`] still accepts (name unknown).
const GROUP_BODY_MAGIC: &[u8] = b"\x00LITG1\x00";

/// Structured inner payload of a private-group frame (format v1). Holds
/// only what a group bubble needs to attribute a message; additive
/// fields stay backward-compatible via serde defaults.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupBodyV1 {
    /// Sender display name, when the sender published one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_name: Option<String>,
    /// Plaintext message body.
    pub body: String,
    /// Per-sender monotonic send counter for this group (starts at 1),
    /// sealed inside the frame so the relay never sees it. Receivers
    /// use it to detect missed messages (a hole in the sequence).
    /// Absent on frames from senders that predate gap detection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
}

/// A decoded private-group plaintext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedGroupBody {
    /// Plaintext message body.
    pub body: String,
    /// Sender display name, when the sender published one.
    pub sender_name: Option<String>,
    /// Per-sender monotonic send counter, when the sender sealed one.
    pub seq: Option<u64>,
}

/// Encode a private-group plaintext that carries the sender display
/// name and per-sender send counter alongside the body. An empty
/// `sender_name` is encoded as absent. Round-trips through
/// [`decode_group_plaintext`].
#[must_use]
pub fn encode_group_plaintext(sender_name: &str, body: &str, seq: Option<u64>) -> Vec<u8> {
    let payload = GroupBodyV1 {
        sender_name: (!sender_name.is_empty()).then(|| sender_name.to_owned()),
        body: body.to_owned(),
        seq,
    };
    let mut out = GROUP_BODY_MAGIC.to_vec();
    // Serializing a String + Option fields cannot fail; default to the
    // bare magic only on the impossible error so the frame stays valid.
    out.extend_from_slice(&serde_json::to_vec(&payload).unwrap_or_default());
    out
}

/// Decode a decrypted private-group plaintext.
/// New frames carry `GROUP_BODY_MAGIC` + JSON; legacy frames are a
/// bare UTF-8 body with no name and no counter. The magic prefix is
/// the only discriminator, so a legacy body that happens to be valid
/// JSON is returned verbatim. Unknown JSON fields from newer senders
/// are ignored, so additive payload evolution stays compatible.
///
/// # Errors
/// Returns a message when a magic-prefixed frame fails to JSON-parse,
/// or a legacy frame is not valid UTF-8.
pub fn decode_group_plaintext(plaintext: &[u8]) -> Result<DecodedGroupBody, String> {
    if let Some(rest) = plaintext.strip_prefix(GROUP_BODY_MAGIC) {
        let payload: GroupBodyV1 =
            serde_json::from_slice(rest).map_err(|e| format!("group payload json: {e}"))?;
        Ok(DecodedGroupBody {
            body: payload.body,
            sender_name: payload.sender_name,
            seq: payload.seq,
        })
    } else {
        let body = String::from_utf8(plaintext.to_vec()).map_err(|e| format!("body utf8: {e}"))?;
        Ok(DecodedGroupBody {
            body,
            sender_name: None,
            seq: None,
        })
    }
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
    /// `message_id` of an earlier message this one replies to. Carries
    /// only the id — receivers reconstruct the quoted preview from
    /// their own local history, so quoted content is never duplicated
    /// on the wire. Absent on non-replies and on payloads from older
    /// senders.
    #[serde(default)]
    pub reply_to_message_id: Option<String>,
    /// Optional inline image attachment. Absent on text-only messages
    /// and on payloads from older senders that do not support spec 2.4.
    #[serde(default)]
    pub attachment: Option<crate::attachment::Attachment>,
    /// Sender's current advertised relay list (in-band relay-hint
    /// refresh). Absent on payloads from pre-Task-6 senders.
    #[serde(default)]
    pub advertised_relays: Option<Vec<String>>,
    /// Sender's current pair-record `issued_at_ms` (freshness watermark
    /// for `advertised_relays`). Absent on payloads from pre-Task-6
    /// senders.
    #[serde(default)]
    pub hint_epoch_ms: Option<u64>,
}

/// Inner payload of a `DeliveryReceipt` envelope.
///
/// The recipient of a `Message` envelope emits a `DeliveryReceipt` back to the
/// original sender once the message has been decrypted. `message_id` echoes
/// the logical message id minted by `random_message_id` (16 random bytes,
/// hex-encoded), matching `HistoryEntry::message_id`, so the sender can
/// correlate the receipt to a specific outbound message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryReceiptPayload {
    /// Hex-encoded logical message id (`HistoryEntry::message_id`) of the
    /// original message envelope.
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
    /// Logical message id (hex). Delivery receipts echo this value
    /// back; [`Conversation::apply_delivery_receipt`] binds them.
    pub message_id: String,
    /// Optional inline image attachment. Unlike `reply_to_message_id`
    /// (which the receiver can reconstruct from local history), image
    /// bytes cannot be re-derived, so they must survive a vault reload.
    #[serde(default)]
    pub attachment: Option<crate::attachment::Attachment>,
    /// Unix-ms when the recipient's delivery receipt for this message
    /// arrived, or `None` while unconfirmed. Only meaningful on entries
    /// this side sent. Persisted so headless readers and vault reloads
    /// see delivery state without replaying receipt events.
    #[serde(default)]
    pub delivered_at_ms: Option<u64>,
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

    fn test_member() -> Member {
        Member {
            user_id_hex: None,
            devices: Vec::new(),
            joined_at_epoch: 0,
        }
    }

    #[test]
    fn record_group_seq_windows_are_independent_per_sender() {
        let mut conv = Conversation::new_dm(test_member(), test_member(), None).unwrap();
        assert_eq!(conv.record_group_seq("bb", 1, 10), SeqObservation::First);
        assert_eq!(
            conv.record_group_seq("bb", 2, 11),
            SeqObservation::Consecutive
        );
        // A second sender starts its own ledger; no cross-talk.
        assert_eq!(conv.record_group_seq("cc", 1, 12), SeqObservation::First);
        assert_eq!(
            conv.record_group_seq("bb", 4, 13),
            SeqObservation::Gap { missing: vec![3] }
        );
        assert_eq!(conv.group_seq_windows.len(), 2);
    }

    #[test]
    fn conversation_json_without_seq_fields_deserializes_with_defaults() {
        // A vault sealed before gap detection has neither field; it must
        // come back with a zero counter and empty ledgers.
        let conv = Conversation::new_dm(test_member(), test_member(), None).unwrap();
        let mut v: serde_json::Value = serde_json::to_value(&conv).unwrap();
        let obj = v.as_object_mut().unwrap();
        assert!(obj.remove("own_group_send_seq").is_some());
        assert!(obj.remove("group_seq_windows").is_some());
        let back: Conversation = serde_json::from_value(v).unwrap();
        assert_eq!(back.own_group_send_seq, 0);
        assert!(back.group_seq_windows.is_empty());
    }

    #[test]
    fn conversation_seq_state_round_trips_through_json() {
        let mut conv = Conversation::new_dm(test_member(), test_member(), None).unwrap();
        conv.own_group_send_seq = 7;
        conv.record_group_seq("bb", 1, 10);
        conv.record_group_seq("bb", 5, 20);
        let json = serde_json::to_string(&conv).unwrap();
        let back: Conversation = serde_json::from_str(&json).unwrap();
        assert_eq!(back.own_group_send_seq, 7);
        assert_eq!(back.group_seq_windows, conv.group_seq_windows);
    }

    #[test]
    fn group_plaintext_round_trips_name_and_body() {
        let enc = encode_group_plaintext("Alice", "hi there", None);
        let d = decode_group_plaintext(&enc).unwrap();
        assert_eq!(d.body, "hi there");
        assert_eq!(d.sender_name.as_deref(), Some("Alice"));
        assert_eq!(d.seq, None);
    }

    #[test]
    fn group_plaintext_round_trips_seq() {
        let enc = encode_group_plaintext("Alice", "counted", Some(42));
        let d = decode_group_plaintext(&enc).unwrap();
        assert_eq!(d.body, "counted");
        assert_eq!(d.seq, Some(42));
    }

    #[test]
    fn group_plaintext_absent_seq_is_not_serialized() {
        // skip_serializing_if keeps seq-less frames byte-identical to the
        // pre-gap-detection format, so old receivers parse them unchanged.
        let enc = encode_group_plaintext("Alice", "plain", None);
        let json = std::str::from_utf8(&enc[GROUP_BODY_MAGIC.len()..]).unwrap();
        assert!(!json.contains("seq"), "unexpected seq key in {json}");
    }

    #[test]
    fn group_plaintext_ignores_unknown_future_fields() {
        // A newer sender may add fields; decode must not reject them.
        let mut frame = GROUP_BODY_MAGIC.to_vec();
        frame.extend_from_slice(br#"{"body":"hi","seq":7,"future_field":true}"#);
        let d = decode_group_plaintext(&frame).unwrap();
        assert_eq!(d.body, "hi");
        assert_eq!(d.seq, Some(7));
    }

    #[test]
    fn group_plaintext_empty_name_encodes_absent() {
        let enc = encode_group_plaintext("", "no name", None);
        let d = decode_group_plaintext(&enc).unwrap();
        assert_eq!(d.body, "no name");
        assert_eq!(d.sender_name, None);
    }

    #[test]
    fn group_plaintext_legacy_bare_body_decodes_with_no_name() {
        // A pre-upgrade sender encrypts the raw body with no magic prefix.
        let d = decode_group_plaintext(b"plain old body").unwrap();
        assert_eq!(d.body, "plain old body");
        assert_eq!(d.sender_name, None);
        assert_eq!(d.seq, None);
    }

    #[test]
    fn group_plaintext_body_with_unicode_and_json_chars_survives() {
        let tricky = r#"{"not":"a payload"} literal, with emoji"#;
        let enc = encode_group_plaintext("Bob", tricky, None);
        let d = decode_group_plaintext(&enc).unwrap();
        assert_eq!(d.body, tricky);
        assert_eq!(d.sender_name.as_deref(), Some("Bob"));
    }

    #[test]
    fn group_plaintext_legacy_body_that_looks_like_json_is_kept_verbatim() {
        // A legacy body that happens to be JSON must NOT be mis-parsed —
        // the magic prefix is the only discriminator.
        let d = decode_group_plaintext(br#"{"body":"x"}"#).unwrap();
        assert_eq!(d.body, r#"{"body":"x"}"#);
        assert_eq!(d.sender_name, None);
    }

    #[test]
    fn message_payload_decodes_legacy_json_without_reply_field() {
        let legacy = r#"{"sender_name":"A","body":"hi","ts_ms":1,"message_id":"m1"}"#;
        let p: MessagePayload = serde_json::from_str(legacy).unwrap();
        assert_eq!(p.reply_to_message_id, None);
        assert_eq!(p.message_id.as_deref(), Some("m1"));
    }

    #[test]
    fn message_payload_round_trips_reply_field() {
        let p = MessagePayload {
            sender_name: Some("A".into()),
            body: "re".into(),
            ts_ms: 2,
            message_id: Some("m2".into()),
            reply_to_message_id: Some("m1".into()),
            attachment: None,
            advertised_relays: None,
            hint_epoch_ms: None,
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: MessagePayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn message_payload_round_trips_attachment_field() {
        use crate::attachment::Attachment;
        let att = Attachment::from_raw("image/png", 4, 4, &[0xABu8; 16]).unwrap();
        let p = MessagePayload {
            sender_name: Some("A".into()),
            body: "look".into(),
            ts_ms: 3,
            message_id: Some("m3".into()),
            reply_to_message_id: None,
            attachment: Some(att),
            advertised_relays: None,
            hint_epoch_ms: None,
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: MessagePayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn message_payload_decodes_legacy_json_without_attachment_field() {
        // Old payloads that predate spec 2.4 must decode to attachment: None.
        let legacy = r#"{"sender_name":"A","body":"hi","ts_ms":1,"message_id":"m1","reply_to_message_id":null}"#;
        let p: MessagePayload = serde_json::from_str(legacy).unwrap();
        assert_eq!(p.attachment, None);
    }

    #[test]
    fn message_payload_pre_task6_json_decodes_hint_fields_as_none() {
        // Pre-Task-6 payloads (no advertised_relays / hint_epoch_ms) must
        // deserialize with both fields None.
        let legacy = r#"{"sender_name":"A","body":"hi","ts_ms":1,"message_id":"m1"}"#;
        let p: MessagePayload = serde_json::from_str(legacy).unwrap();
        assert_eq!(p.advertised_relays, None);
        assert_eq!(p.hint_epoch_ms, None);
    }

    #[test]
    fn message_payload_round_trips_hint_fields() {
        let p = MessagePayload {
            sender_name: Some("A".into()),
            body: "hi".into(),
            ts_ms: 1,
            message_id: Some("m1".into()),
            reply_to_message_id: None,
            attachment: None,
            advertised_relays: Some(vec!["wss://relay.example.com".to_owned()]),
            hint_epoch_ms: Some(42_000),
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: MessagePayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back.advertised_relays, p.advertised_relays);
        assert_eq!(back.hint_epoch_ms, p.hint_epoch_ms);
    }

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
            own_group_send_seq: 0,
            group_seq_windows: BTreeMap::new(),
            wedge_last_progress_ms: 0,
            wedge_last_inbound_ms: 0,
            wedge_progress_epoch: 0,
            wedge_max_stale_epoch: 0,
            read_ms: 0,
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
            own_group_send_seq: 0,
            group_seq_windows: BTreeMap::new(),
            wedge_last_progress_ms: 0,
            wedge_last_inbound_ms: 0,
            wedge_progress_epoch: 0,
            wedge_max_stale_epoch: 0,
            read_ms: 0,
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
            own_group_send_seq: 0,
            group_seq_windows: BTreeMap::new(),
            wedge_last_progress_ms: 0,
            wedge_last_inbound_ms: 0,
            wedge_progress_epoch: 0,
            wedge_max_stale_epoch: 0,
            read_ms: 0,
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
            own_group_send_seq: 0,
            group_seq_windows: BTreeMap::new(),
            wedge_last_progress_ms: 0,
            wedge_last_inbound_ms: 0,
            wedge_progress_epoch: 0,
            wedge_max_stale_epoch: 0,
            read_ms: 0,
        };
        assert!(!conv.auto_rekey_due(), "Member role must not auto-rekey");
    }

    /// Build a conversation at `epoch` holding `key`.
    fn conv_at(epoch: u32, key: [u8; 32]) -> Conversation {
        Conversation {
            group_id_hex: "0".repeat(64),
            name: None,
            members: vec![],
            current_epoch: epoch,
            current_key_b64: B64.encode(key),
            prior_keys: vec![],
            own_role: Role::Admin,
            created_at_ms: 0,
            last_rekey_at_ms: 0,
            auto_rekey_interval_ms: 1,
            trust_state: TrustState::Confirmed,
            seen_nonces: BTreeMap::new(),
            history: VecDeque::new(),
            own_group_send_seq: 0,
            group_seq_windows: BTreeMap::new(),
            wedge_last_progress_ms: 0,
            wedge_last_inbound_ms: 0,
            wedge_progress_epoch: 0,
            wedge_max_stale_epoch: 0,
            read_ms: 0,
        }
    }

    /// #297 regression. The forced re-key jumps past the peer's epoch,
    /// and the outgoing key MUST be archived under the epoch it actually
    /// served. Filing it under the jump target instead (the original
    /// `current_epoch = floor; advance_epoch()` form) loses every
    /// in-flight frame at our real epoch AND makes a genuine frame at
    /// the target open with the wrong key.
    #[test]
    fn advance_epoch_to_archives_the_outgoing_key_at_its_true_epoch() {
        let live = [7u8; 32];
        let mut conv = conv_at(3, live);

        conv.advance_epoch_to(7, [9u8; 32]);

        assert_eq!(conv.current_epoch, 8, "must land past the peer's epoch");
        assert_eq!(
            conv.key_for_epoch(3).unwrap(),
            Some(live),
            "the epoch-3 key must still open epoch-3 frames",
        );
        assert_eq!(
            conv.key_for_epoch(7).unwrap(),
            None,
            "we never served epoch 7; claiming that key would decrypt a \
             genuine epoch-7 frame with the wrong key",
        );
    }

    /// A floor at or below our own epoch is the ordinary +1 advance.
    #[test]
    fn advance_epoch_to_below_current_still_advances_by_one() {
        let mut conv = conv_at(5, [1u8; 32]);
        conv.advance_epoch_to(2, [2u8; 32]);
        assert_eq!(conv.current_epoch, 6);
    }

    /// The floor is derived from a peer-supplied epoch. Wrapping to 0
    /// would strand the conversation below every future Welcome (`<=`
    /// is ignored) with no way back.
    #[test]
    fn advance_epoch_to_saturates_instead_of_wrapping() {
        let mut conv = conv_at(u32::MAX - 1, [1u8; 32]);
        conv.advance_epoch_to(u32::MAX, [2u8; 32]);
        assert_eq!(conv.current_epoch, u32::MAX, "must clamp, never wrap to 0");
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
            own_group_send_seq: 0,
            group_seq_windows: BTreeMap::new(),
            wedge_last_progress_ms: 0,
            wedge_last_inbound_ms: 0,
            wedge_progress_epoch: 0,
            wedge_max_stale_epoch: 0,
            read_ms: 0,
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
            own_group_send_seq: 0,
            group_seq_windows: BTreeMap::new(),
            wedge_last_progress_ms: 0,
            wedge_last_inbound_ms: 0,
            wedge_progress_epoch: 0,
            wedge_max_stale_epoch: 0,
            read_ms: 0,
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
            own_group_send_seq: 0,
            group_seq_windows: BTreeMap::new(),
            wedge_last_progress_ms: 0,
            wedge_last_inbound_ms: 0,
            wedge_progress_epoch: 0,
            wedge_max_stale_epoch: 0,
            read_ms: 0,
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
            own_group_send_seq: 0,
            group_seq_windows: BTreeMap::new(),
            wedge_last_progress_ms: 0,
            wedge_last_inbound_ms: 0,
            wedge_progress_epoch: 0,
            wedge_max_stale_epoch: 0,
            read_ms: 0,
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
            own_group_send_seq: 0,
            group_seq_windows: BTreeMap::new(),
            wedge_last_progress_ms: 0,
            wedge_last_inbound_ms: 0,
            wedge_progress_epoch: 0,
            wedge_max_stale_epoch: 0,
            read_ms: 0,
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
            own_group_send_seq: 0,
            group_seq_windows: BTreeMap::new(),
            wedge_last_progress_ms: 0,
            wedge_last_inbound_ms: 0,
            wedge_progress_epoch: 0,
            wedge_max_stale_epoch: 0,
            read_ms: 0,
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
                attachment: None,
                delivered_at_ms: None,
            });
        }
        assert_eq!(conv.history.len(), Conversation::HISTORY_CAP);
        assert_eq!(conv.history.front().unwrap().body, "m1");
        assert_eq!(conv.history.back().unwrap().body, "m1000");
    }

    fn history_entry(message_id: &str) -> HistoryEntry {
        HistoryEntry {
            sender_agent_id_hex: "a".repeat(64),
            sender_name: None,
            body: "hi".into(),
            ts_ms: 1,
            message_id: message_id.into(),
            attachment: None,
            delivered_at_ms: None,
        }
    }

    #[test]
    fn apply_delivery_receipt_marks_the_matching_entry() {
        let mut conv = make_minimal_conversation_for_history_test();
        conv.push_history(history_entry("aa"));
        conv.push_history(history_entry("bb"));
        assert!(conv.apply_delivery_receipt("aa", 777));
        let marked = conv.history.iter().find(|e| e.message_id == "aa").unwrap();
        assert_eq!(marked.delivered_at_ms, Some(777));
        let other = conv.history.iter().find(|e| e.message_id == "bb").unwrap();
        assert_eq!(other.delivered_at_ms, None);
    }

    #[test]
    fn apply_delivery_receipt_unknown_id_is_false() {
        let mut conv = make_minimal_conversation_for_history_test();
        conv.push_history(history_entry("aa"));
        assert!(!conv.apply_delivery_receipt("zz", 777));
    }

    #[test]
    fn apply_delivery_receipt_duplicate_is_false_and_keeps_first_ts() {
        // A duplicate receipt must not move the recorded time and must
        // signal no-op so the registry skips a redundant disk write.
        let mut conv = make_minimal_conversation_for_history_test();
        conv.push_history(history_entry("aa"));
        assert!(conv.apply_delivery_receipt("aa", 100));
        assert!(!conv.apply_delivery_receipt("aa", 999));
        let e = conv.history.iter().find(|e| e.message_id == "aa").unwrap();
        assert_eq!(e.delivered_at_ms, Some(100));
    }

    const LOCAL: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const PEER: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn entry_from(sender: &str, ts_ms: u64) -> HistoryEntry {
        HistoryEntry {
            sender_agent_id_hex: sender.to_owned(),
            sender_name: None,
            body: format!("m{ts_ms}"),
            ts_ms,
            message_id: format!("{sender}-{ts_ms}"),
            attachment: None,
            delivered_at_ms: None,
        }
    }

    #[test]
    fn a_never_opened_conversation_counts_its_whole_inbound_history() {
        // The badge is the only signal a message landed while the app was
        // closed, so an unopened conversation is unread by construction.
        let mut conv = make_minimal_conversation_for_history_test();
        conv.push_history(entry_from(PEER, 100));
        conv.push_history(entry_from(PEER, 200));
        assert_eq!(conv.unread(LOCAL), 2);
    }

    #[test]
    fn our_own_sends_are_never_unread() {
        let mut conv = make_minimal_conversation_for_history_test();
        conv.push_history(entry_from(LOCAL, 100));
        conv.push_history(entry_from(LOCAL, 200));
        assert_eq!(conv.unread(LOCAL), 0);
        // Including the group echo shape: our own send sits between two
        // peer messages and must not inflate the count.
        conv.push_history(entry_from(PEER, 300));
        assert_eq!(conv.unread(LOCAL), 1);
    }

    #[test]
    fn mark_read_clears_unread_and_a_later_message_re_arms_it() {
        let mut conv = make_minimal_conversation_for_history_test();
        conv.push_history(entry_from(PEER, 100));
        conv.push_history(entry_from(PEER, 200));
        assert!(conv.mark_read(), "the mark moved");
        assert_eq!(conv.unread(LOCAL), 0);
        assert!(!conv.mark_read(), "re-opening a read thread is a no-op");

        conv.push_history(entry_from(PEER, 300));
        assert_eq!(conv.unread(LOCAL), 1);
    }

    #[test]
    fn mark_read_covers_everything_on_screen_not_just_the_last_arrival() {
        // Relay store-and-forward replays out of order: a message that
        // arrives last can carry an older stamp. The thread screen sorts
        // by stamp and shows all of it, so reading it reads all of it —
        // marking only up to the LAST arrival would leave the newest
        // message permanently badged.
        let mut conv = make_minimal_conversation_for_history_test();
        conv.push_history(entry_from(PEER, 300));
        conv.push_history(entry_from(PEER, 100));
        assert!(conv.mark_read());
        assert_eq!(conv.unread(LOCAL), 0);
    }

    #[test]
    fn mark_read_on_an_empty_conversation_stores_nothing() {
        let mut conv = make_minimal_conversation_for_history_test();
        assert!(!conv.mark_read());
        assert_eq!(conv.read_ms, 0);
        assert_eq!(conv.unread(LOCAL), 0);
    }

    #[test]
    fn read_mark_survives_the_json_round_trip() {
        let mut conv = make_minimal_conversation_for_history_test();
        conv.push_history(entry_from(PEER, 100));
        assert!(conv.mark_read());
        let back: Conversation =
            serde_json::from_str(&serde_json::to_string(&conv).unwrap()).unwrap();
        assert_eq!(back.read_ms, conv.read_ms);
        assert_eq!(back.unread(LOCAL), 0);
    }

    #[test]
    fn a_vault_sealed_before_read_marks_decodes_as_all_unread() {
        // Pre-existing conversations have no read_ms; they must come back
        // unread rather than failing to decode or starting silenced.
        let mut conv = make_minimal_conversation_for_history_test();
        conv.push_history(entry_from(PEER, 100));
        let mut v: serde_json::Value = serde_json::to_value(&conv).unwrap();
        assert!(v.as_object_mut().unwrap().remove("read_ms").is_some());
        let back: Conversation = serde_json::from_value(v).unwrap();
        assert_eq!(back.read_ms, 0);
        assert_eq!(back.unread(LOCAL), 1);
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
