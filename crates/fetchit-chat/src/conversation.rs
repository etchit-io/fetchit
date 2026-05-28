//! Conversation state and lifecycle for chat encryption.
//!
//! A `Conversation` represents one DM or group. v1 ships 2-member
//! conversations (DMs); v3 adds N-member groups. Data shape supports
//! N from day one.
//!
//! Storage: each Conversation is persisted to
//! `<conversations_dir>/<group_id_hex>.json.enc` via `at_rest`.

use crate::at_rest::{open_from_path, seal_to_path, MasterKey, ARGON_SALT_LEN};
use crate::chat_crypto::{
    aead_open, aead_seal, canonical_envelope_bytes, derive_aead_key, kem_decapsulate,
    kem_encapsulate, message_aad, random_nonce, random_symmetric_key, AEAD_KEY_LEN,
    KDF_INFO_WELCOME, KEM_PUBLIC_KEY_LEN,
};
use crate::chat_identity::FetchitIdentity;
use crate::error::ChatError;
use crate::local_store::StoreLayout;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use fetchit_relay_proto::{AgentId, EnvelopeKind, GroupId, MachineId, TransitEnvelope};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

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
        let key = random_symmetric_key(&mut OsRng);
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

/// In-memory registry of open conversations, persisted via `at_rest`.
pub struct ConversationRegistry {
    layout: StoreLayout,
    master: Arc<MasterKey>,
    kdf_id: u8,
    argon_salt: Option<[u8; ARGON_SALT_LEN]>,
    by_group_id: Mutex<HashMap<String, Conversation>>,
}

impl ConversationRegistry {
    /// Build an empty registry. Conversations are loaded on demand.
    #[must_use]
    pub fn new(
        layout: StoreLayout,
        master: Arc<MasterKey>,
        kdf_id: u8,
        argon_salt: Option<[u8; ARGON_SALT_LEN]>,
    ) -> Self {
        Self {
            layout,
            master,
            kdf_id,
            argon_salt,
            by_group_id: Mutex::new(HashMap::new()),
        }
    }

    /// Borrow / load a conversation by `group_id_hex`.
    /// Returns None if it's not on disk and not in memory.
    ///
    /// # Errors
    /// IO, AEAD, or JSON parse errors.
    pub async fn get(&self, group_id_hex: &str) -> Result<Option<Conversation>, ChatError> {
        {
            let g = self.by_group_id.lock().await;
            if let Some(c) = g.get(group_id_hex) {
                return Ok(Some(c.clone()));
            }
        }
        let path = self.layout.conversation_path(group_id_hex);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = open_from_path(&path, &self.master)?;
        let conv: Conversation = serde_json::from_slice(&bytes)
            .map_err(|e| ChatError::Invalid(format!("conv parse: {e}")))?;
        self.by_group_id
            .lock()
            .await
            .insert(group_id_hex.to_owned(), conv.clone());
        Ok(Some(conv))
    }

    /// Find an existing DM with `peer_agent_id_hex` (any conversation
    /// that has exactly 2 members and one of them is the peer).
    ///
    /// # Errors
    /// IO or vault open failures while scanning disk.
    pub async fn find_dm_with(
        &self,
        peer_agent_id_hex: &str,
    ) -> Result<Option<Conversation>, ChatError> {
        {
            let g = self.by_group_id.lock().await;
            for c in g.values() {
                if dm_with(c, peer_agent_id_hex) {
                    return Ok(Some(c.clone()));
                }
            }
        }
        for entry in std::fs::read_dir(&self.layout.conversations_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("enc") {
                continue;
            }
            let bytes = open_from_path(&path, &self.master)?;
            let conv: Conversation = serde_json::from_slice(&bytes)
                .map_err(|e| ChatError::Invalid(format!("conv parse: {e}")))?;
            if dm_with(&conv, peer_agent_id_hex) {
                self.by_group_id
                    .lock()
                    .await
                    .insert(conv.group_id_hex.clone(), conv.clone());
                return Ok(Some(conv));
            }
        }
        Ok(None)
    }

    /// Persist a conversation to disk and update the in-memory cache.
    ///
    /// # Errors
    /// IO, AEAD seal, or JSON serialize errors.
    pub async fn save(&self, conv: &Conversation) -> Result<(), ChatError> {
        let path = self.layout.conversation_path(&conv.group_id_hex);
        let bytes = serde_json::to_vec(conv)
            .map_err(|e| ChatError::Invalid(format!("conv serialize: {e}")))?;
        seal_to_path(
            &path,
            &bytes,
            &self.master,
            self.kdf_id,
            self.argon_salt.as_ref(),
        )?;
        self.by_group_id
            .lock()
            .await
            .insert(conv.group_id_hex.clone(), conv.clone());
        Ok(())
    }
}

fn dm_with(conv: &Conversation, peer_agent_id_hex: &str) -> bool {
    if conv.members.len() != 2 {
        return false;
    }
    conv.members
        .iter()
        .flat_map(|m| m.devices.iter())
        .any(|d| d.agent_id_hex == peer_agent_id_hex)
}

/// Tuple convenience: an outbound envelope paired with its recipient.
#[derive(Clone, Debug)]
pub struct OutboundEnvelope {
    /// The recipient agent id (one entry per recipient device).
    pub recipient_agent_id: AgentId,
    /// The signed, sealed envelope.
    pub envelope: TransitEnvelope,
}

/// Build the set of Welcome envelopes Alice needs to send when starting
/// a new conversation. One envelope per recipient device.
///
/// # Errors
/// KEM / AEAD / signing errors.
pub async fn build_welcome_outbox<S: fetchit_relay_client::Signer + ?Sized>(
    conv: &Conversation,
    identity: &FetchitIdentity,
    local_machine_id: [u8; 32],
    signer: &S,
) -> Result<Vec<OutboundEnvelope>, ChatError> {
    let payload = WelcomePayload {
        group_id_hex: conv.group_id_hex.clone(),
        current_key_b64: conv.current_key_b64.clone(),
        epoch: conv.current_epoch,
        members: conv.members.clone(),
        name: conv.name.clone(),
    };
    let payload_bytes = serde_json::to_vec(&payload)
        .map_err(|e| ChatError::Invalid(format!("welcome serialize: {e}")))?;

    let group_id_bytes = conv.group_id_bytes()?;
    let mut local_agent_bytes = [0u8; 32];
    hex::decode_to_slice(identity.agent_id_hex(), &mut local_agent_bytes)
        .map_err(|e| ChatError::Invalid(format!("local agent_id hex: {e}")))?;

    let local_agent_hex = identity.agent_id_hex().to_owned();
    let mut out = Vec::new();

    for device in conv.fanout_devices(&local_agent_hex) {
        let kem_pub = B64
            .decode(&device.kem_public_key_b64)
            .map_err(|e| ChatError::Invalid(format!("device kem b64: {e}")))?;
        if kem_pub.len() != KEM_PUBLIC_KEY_LEN {
            return Err(ChatError::Invalid("device kem key length".into()));
        }
        let (kem_ct, ss) = kem_encapsulate(&kem_pub)?;
        let aead_key = derive_aead_key(&ss, KDF_INFO_WELCOME);
        let nonce = random_nonce(&mut OsRng);
        let aad = message_aad(&group_id_bytes, conv.current_epoch);
        let ciphertext = aead_seal(&aead_key, &nonce, &payload_bytes, &aad)?;

        let mut recipient_agent = [0u8; 32];
        hex::decode_to_slice(&device.agent_id_hex, &mut recipient_agent)
            .map_err(|e| ChatError::Invalid(format!("recipient agent_id hex: {e}")))?;

        let mut env = TransitEnvelope {
            version: 2,
            kind: EnvelopeKind::GroupChat,
            group_id: Some(GroupId::from_bytes(group_id_bytes)),
            tenant_id: None,
            sender_agent_id: AgentId::from_bytes(local_agent_bytes),
            sender_machine_id: MachineId::from_bytes(local_machine_id),
            timestamp_ms: now_ms(),
            epoch: conv.current_epoch,
            ciphertext,
            nonce: nonce.to_vec(),
            kem_ciphertext: kem_ct,
            sender_signature: Vec::new(),
        };
        let canonical = canonical_envelope_bytes(&env)?;
        let mut sign_bytes =
            Vec::with_capacity(crate::chat_crypto::SIGN_DOMAIN_ENVELOPE.len() + canonical.len());
        sign_bytes.extend_from_slice(crate::chat_crypto::SIGN_DOMAIN_ENVELOPE);
        sign_bytes.extend_from_slice(&canonical);
        let sig = signer
            .sign(&sign_bytes)
            .await
            .map_err(|e| ChatError::Invalid(format!("envelope sign: {e}")))?;
        env.sender_signature = sig;

        out.push(OutboundEnvelope {
            recipient_agent_id: AgentId::from_bytes(recipient_agent),
            envelope: env,
        });
    }
    Ok(out)
}

/// Build outbound Message envelopes for a chat message in `conv`.
///
/// # Errors
/// AEAD or signing errors.
pub async fn build_message_outbox<S: fetchit_relay_client::Signer + ?Sized>(
    conv: &Conversation,
    body: &str,
    sender_name: &str,
    identity: &FetchitIdentity,
    local_machine_id: [u8; 32],
    signer: &S,
) -> Result<Vec<OutboundEnvelope>, ChatError> {
    let now = now_ms();
    let payload = MessagePayload {
        sender_name: Some(sender_name.to_owned()),
        body: body.to_owned(),
        ts_ms: now,
    };
    let payload_bytes = serde_json::to_vec(&payload)
        .map_err(|e| ChatError::Invalid(format!("message serialize: {e}")))?;

    let key = conv.current_key()?;
    let group_id_bytes = conv.group_id_bytes()?;
    let aad = message_aad(&group_id_bytes, conv.current_epoch);

    let mut local_agent_bytes = [0u8; 32];
    hex::decode_to_slice(identity.agent_id_hex(), &mut local_agent_bytes)
        .map_err(|e| ChatError::Invalid(format!("local agent_id hex: {e}")))?;

    let local_agent_hex = identity.agent_id_hex().to_owned();
    let mut out = Vec::new();
    for device in conv.fanout_devices(&local_agent_hex) {
        let nonce = random_nonce(&mut OsRng);
        let ciphertext = aead_seal(&key, &nonce, &payload_bytes, &aad)?;
        let mut recipient_agent = [0u8; 32];
        hex::decode_to_slice(&device.agent_id_hex, &mut recipient_agent)
            .map_err(|e| ChatError::Invalid(format!("recipient hex: {e}")))?;

        let mut env = TransitEnvelope {
            version: 2,
            kind: EnvelopeKind::GroupChat,
            group_id: Some(GroupId::from_bytes(group_id_bytes)),
            tenant_id: None,
            sender_agent_id: AgentId::from_bytes(local_agent_bytes),
            sender_machine_id: MachineId::from_bytes(local_machine_id),
            timestamp_ms: now,
            epoch: conv.current_epoch,
            ciphertext,
            nonce: nonce.to_vec(),
            kem_ciphertext: Vec::new(),
            sender_signature: Vec::new(),
        };
        let canonical = canonical_envelope_bytes(&env)?;
        let mut sign_bytes =
            Vec::with_capacity(crate::chat_crypto::SIGN_DOMAIN_ENVELOPE.len() + canonical.len());
        sign_bytes.extend_from_slice(crate::chat_crypto::SIGN_DOMAIN_ENVELOPE);
        sign_bytes.extend_from_slice(&canonical);
        let sig = signer
            .sign(&sign_bytes)
            .await
            .map_err(|e| ChatError::Invalid(format!("envelope sign: {e}")))?;
        env.sender_signature = sig;

        out.push(OutboundEnvelope {
            recipient_agent_id: AgentId::from_bytes(recipient_agent),
            envelope: env,
        });
    }
    Ok(out)
}

/// Inbound dispatch result.
#[derive(Clone, Debug)]
pub enum InboundDispatch {
    /// Installed a new conversation (from a welcome).
    Welcomed {
        /// The freshly installed conversation.
        conversation: Conversation,
    },
    /// Updated an existing conversation (welcome carrying a higher epoch).
    Rekeyed {
        /// The updated conversation.
        conversation: Conversation,
    },
    /// Decrypted a chat message.
    Message {
        /// Hex group id.
        group_id_hex: String,
        /// Hex sender agent id.
        sender_agent_id_hex: String,
        /// Decoded payload.
        payload: MessagePayload,
    },
    /// Stale epoch — dropped.
    StaleEpoch {
        /// Hex group id.
        group_id_hex: String,
        /// The envelope epoch.
        epoch: u32,
    },
    /// KEM decap failed (likely encrypted to a different KEM key).
    KemDecapFailed,
    /// AEAD open failed (likely tampered or wrong key).
    AeadOpenFailed {
        /// Hex group id.
        group_id_hex: String,
        /// The envelope epoch.
        epoch: u32,
    },
}

/// Dispatch an inbound envelope: distinguish Welcome vs Message,
/// decrypt, and surface a typed result.
///
/// # Errors
/// Hard errors (e.g. malformed envelope bytes). Soft errors (stale
/// epoch, decap fail) are returned as `InboundDispatch` variants.
pub async fn dispatch_inbound(
    envelope: TransitEnvelope,
    identity: &FetchitIdentity,
    registry: &ConversationRegistry,
) -> Result<InboundDispatch, ChatError> {
    let group_id_bytes = match &envelope.group_id {
        Some(g) => *g.as_bytes(),
        None => return Err(ChatError::Invalid("envelope has no group_id".into())),
    };
    let group_id_hex = hex::encode(group_id_bytes);

    if envelope.kem_ciphertext.is_empty() {
        // Message path.
        let Some(conv) = registry.get(&group_id_hex).await? else {
            return Ok(InboundDispatch::StaleEpoch {
                group_id_hex,
                epoch: envelope.epoch,
            });
        };
        let Some(key) = conv.key_for_epoch(envelope.epoch)? else {
            return Ok(InboundDispatch::StaleEpoch {
                group_id_hex,
                epoch: envelope.epoch,
            });
        };
        if envelope.nonce.len() != 12 {
            return Err(ChatError::Invalid("nonce length".into()));
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&envelope.nonce);
        let aad = message_aad(&group_id_bytes, envelope.epoch);
        let Ok(plaintext) = aead_open(&key, &nonce, &envelope.ciphertext, &aad) else {
            return Ok(InboundDispatch::AeadOpenFailed {
                group_id_hex,
                epoch: envelope.epoch,
            });
        };
        let payload: MessagePayload = serde_json::from_slice(&plaintext)
            .map_err(|e| ChatError::Invalid(format!("message payload parse: {e}")))?;
        Ok(InboundDispatch::Message {
            group_id_hex,
            sender_agent_id_hex: hex::encode(envelope.sender_agent_id.as_bytes()),
            payload,
        })
    } else {
        // Welcome path.
        let Ok(ss) = kem_decapsulate(identity.kem_secret_key(), &envelope.kem_ciphertext) else {
            return Ok(InboundDispatch::KemDecapFailed);
        };
        let aead_key = derive_aead_key(&ss, KDF_INFO_WELCOME);
        if envelope.nonce.len() != 12 {
            return Err(ChatError::Invalid("nonce length".into()));
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&envelope.nonce);
        let aad = message_aad(&group_id_bytes, envelope.epoch);
        let Ok(plaintext) = aead_open(&aead_key, &nonce, &envelope.ciphertext, &aad) else {
            return Ok(InboundDispatch::AeadOpenFailed {
                group_id_hex,
                epoch: envelope.epoch,
            });
        };
        let payload: WelcomePayload = serde_json::from_slice(&plaintext)
            .map_err(|e| ChatError::Invalid(format!("welcome payload parse: {e}")))?;
        let existing = registry.get(&group_id_hex).await?;
        match existing {
            Some(conv) if envelope.epoch <= conv.current_epoch => {
                // Stale or current — no-op.
                Ok(InboundDispatch::Welcomed { conversation: conv })
            }
            Some(mut conv) => {
                // Higher epoch — adopt new key and member list. Don't
                // advance_epoch(); we're not generating a fresh key here,
                // we're adopting the one carried in the welcome. We do
                // push the OLD key into prior_keys so in-flight messages
                // can still decrypt for up to PRIOR_KEY_WINDOW_MS.
                let now = now_ms();
                conv.prior_keys.push(PriorKey {
                    epoch: conv.current_epoch,
                    key_b64: conv.current_key_b64.clone(),
                    expires_at_ms: now + PRIOR_KEY_WINDOW_MS,
                });
                conv.current_epoch = payload.epoch;
                conv.current_key_b64 = payload.current_key_b64.clone();
                conv.members = payload.members.clone();
                conv.name = payload.name.clone();
                conv.last_rekey_at_ms = now;
                conv.sweep_prior_keys();
                registry.save(&conv).await?;
                Ok(InboundDispatch::Rekeyed { conversation: conv })
            }
            None => {
                let conv = Conversation::from_welcome(payload);
                registry.save(&conv).await?;
                Ok(InboundDispatch::Welcomed { conversation: conv })
            }
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::at_rest::{fresh_argon_salt, kdf_id_argon2, MasterKeySource};
    use fetchit_relay_client::MlDsaSigner;
    use std::path::Path;
    use tempfile::tempdir;

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

    fn fixture_identity(
        tmp: &Path,
        agent_id_hex: &str,
    ) -> (FetchitIdentity, MasterKey, [u8; ARGON_SALT_LEN]) {
        let salt = fresh_argon_salt();
        let master =
            MasterKey::resolve(&MasterKeySource::Passphrase("p".into()), Some(&salt)).unwrap();
        let id = FetchitIdentity::load_or_create(
            tmp,
            &master,
            agent_id_hex,
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();
        (id, master, salt)
    }

    #[tokio::test]
    async fn welcome_round_trip_between_two_identities() {
        let tmp_a = tempdir().unwrap();
        let aid_a = "aa".repeat(32);
        let (alice_id, _master_a, _salt_a) = fixture_identity(tmp_a.path(), &aid_a);
        let tmp_b = tempdir().unwrap();
        let aid_b = "bb".repeat(32);
        let (bob_id, master_b, salt_b) = fixture_identity(tmp_b.path(), &aid_b);

        let alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();
        let alice_signer = MlDsaSigner::generate().unwrap();

        let outbox = build_welcome_outbox(&conv, &alice_id, [0u8; 32], &alice_signer)
            .await
            .unwrap();
        assert_eq!(outbox.len(), 1);

        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));
        let result = dispatch_inbound(outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();
        match result {
            InboundDispatch::Welcomed { conversation } => {
                assert_eq!(conversation.group_id_hex, conv.group_id_hex);
                assert_eq!(conversation.current_key_b64, conv.current_key_b64);
                assert_eq!(conversation.members.len(), 2);
            }
            other => panic!("expected Welcomed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn message_round_trip_after_welcome() {
        let tmp_a = tempdir().unwrap();
        let aid_a = "aa".repeat(32);
        let (alice_id, _master_a, _salt_a) = fixture_identity(tmp_a.path(), &aid_a);
        let tmp_b = tempdir().unwrap();
        let aid_b = "bb".repeat(32);
        let (bob_id, master_b, salt_b) = fixture_identity(tmp_b.path(), &aid_b);
        let alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();
        let alice_signer = MlDsaSigner::generate().unwrap();

        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));
        let welcome_outbox = build_welcome_outbox(&conv, &alice_id, [0u8; 32], &alice_signer)
            .await
            .unwrap();
        let _ = dispatch_inbound(welcome_outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();

        let msg_outbox = build_message_outbox(
            &conv,
            "hello bob",
            "Alice",
            &alice_id,
            [0u8; 32],
            &alice_signer,
        )
        .await
        .unwrap();
        assert_eq!(msg_outbox.len(), 1);
        let result = dispatch_inbound(msg_outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();
        match result {
            InboundDispatch::Message { payload, .. } => {
                assert_eq!(payload.body, "hello bob");
                assert_eq!(payload.sender_name.as_deref(), Some("Alice"));
            }
            other => panic!("expected Message, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stale_epoch_is_surfaced_not_panicked() {
        let tmp_b = tempdir().unwrap();
        let aid_b = "bb".repeat(32);
        let (bob_id, master_b, salt_b) = fixture_identity(tmp_b.path(), &aid_b);
        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));
        let env = TransitEnvelope {
            version: 2,
            kind: EnvelopeKind::GroupChat,
            group_id: Some(GroupId::from_bytes([0xee; 32])),
            tenant_id: None,
            sender_agent_id: AgentId::from_bytes([0xaa; 32]),
            sender_machine_id: MachineId::from_bytes([0; 32]),
            timestamp_ms: 1,
            epoch: 99,
            ciphertext: vec![0u8; 16],
            nonce: vec![0u8; 12],
            kem_ciphertext: Vec::new(),
            sender_signature: Vec::new(),
        };
        let result = dispatch_inbound(env, &bob_id, &registry_b).await.unwrap();
        assert!(matches!(result, InboundDispatch::StaleEpoch { .. }));
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
