//! Signed pairing records that let relay servers verify a client owns
//! the ML-DSA-65 key it claims.
//!
//! Two record types share this module:
//!
//! - [`PairRecordV1`] — the initial registration card: agent id, ML-DSA
//!   pubkey, ML-KEM-768 pubkey, preferred relays, and a timestamp.
//! - [`ForwardingRecordV1`] — a lightweight migration card that an agent
//!   signs when it switches relay sets without reissuing its full key
//!   material.
//!
//! Both record types carry a detached ML-DSA-65 signature (`sig_b64`)
//! over a **canonical signing input** defined below. The canonical
//! layout is frozen wire format: changing it requires a v2 migration,
//! not a patch.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Domain separator for [`PairRecordV1`] signing inputs.
///
/// **Frozen.** Relay servers and third-party verifiers depend on this
/// exact byte string; changing it is a v2 migration.
pub const PAIR_RECORD_DOMAIN: &[u8] = b"fetchit-pair-record-v1";

/// Domain separator for [`ForwardingRecordV1`] signing inputs.
///
/// **Frozen.** Same constraint as [`PAIR_RECORD_DOMAIN`].
pub const FORWARDING_DOMAIN: &[u8] = b"fetchit-forwarding-v1";

/// Wire `record_version` value carried by every [`PairRecordV1`].
///
/// This is an **unsigned deserialization selector**, not part of the
/// signed canonical layout. The authoritative version binding is the
/// domain separator baked into the signature ([`PAIR_RECORD_DOMAIN`]);
/// `record_version` only routes wire bytes to the right record type once
/// newer versions (a user-scoped v4 record) share the same transport.
/// Legacy records written before the field deserialize to this value.
pub const RECORD_VERSION_V1: u8 = 1;

fn default_record_version_v1() -> u8 {
    RECORD_VERSION_V1
}

/// Domain separator for [`PairRecordV4`] signing inputs.
///
/// **Frozen.** Same constraint as [`PAIR_RECORD_DOMAIN`]; a v5 record
/// gets its own separator, never a patch to this one.
pub const PAIR_RECORD_V4_DOMAIN: &[u8] = b"fetchit-pair-record-v4";

/// Wire `record_version` value carried by every [`PairRecordV4`].
pub const RECORD_VERSION_V4: u8 = 4;

/// Maximum number of devices bound under one user in a [`PairRecordV4`]
/// (the M6 device cap).
const MAX_DEVICES: usize = 5;

fn default_record_version_v4() -> u8 {
    RECORD_VERSION_V4
}

/// Maximum number of relay URLs in either record type.
const MAX_RELAYS: usize = 4;

/// Maximum byte length of a single relay URL.
const MAX_URL_BYTES: usize = 256;

/// A signed pairing record binding an agent's ML-DSA-65 identity key
/// and ML-KEM-768 encryption key to a set of preferred relay URLs.
///
/// The `sig_b64` field is an ML-DSA-65 signature over the canonical
/// signing input produced by [`pair_signing_input`]. Verify with
/// [`verify_pair_record`].
///
/// # Wire representation
///
/// All byte fields are stored as base64 strings (standard alphabet,
/// padded). The struct serialises directly with serde; no serde-with
/// wrappers are needed because callers pass already-encoded strings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairRecordV1 {
    /// Wire-format selector; see [`RECORD_VERSION_V1`]. Unsigned: it is
    /// not part of [`pair_signing_input`], so carrying it leaves existing
    /// signatures and the v1 wire byte-identical. Legacy JSON without the
    /// field deserialises to [`RECORD_VERSION_V1`].
    #[serde(default = "default_record_version_v1")]
    pub record_version: u8,
    /// Lowercase 64-hex SHA-256 agent id derived from the ML-DSA-65
    /// pubkey via [`crate::derive_agent_id`].
    pub agent_id_hex: String,
    /// ML-DSA-65 public key, STANDARD base64-encoded.
    pub ml_dsa_pubkey_b64: String,
    /// ML-KEM-768 public key, STANDARD base64-encoded.
    pub kem_pubkey_b64: String,
    /// Preferred relay URLs in priority order (1..=4 entries, each
    /// a valid http/https URL of at most 256 bytes).
    pub advertised_relays: Vec<String>,
    /// Millisecond timestamp at record issuance. The issuer must
    /// maintain a monotonically increasing watermark per agent; this
    /// module does not enforce that -- see [`verify_pair_record`].
    pub issued_at_ms: u64,
    /// ML-DSA-65 signature over [`pair_signing_input`], STANDARD
    /// base64-encoded.
    pub sig_b64: String,
}

/// A signed forwarding record redirecting an agent's relay set.
///
/// Forwarding records carry no key material; the verifier supplies the
/// agent's known ML-DSA-65 pubkey (from the stored [`PairRecordV1`] or
/// an out-of-band key exchange). Verify with
/// [`verify_forwarding_record`].
///
/// # Wire representation
///
/// Same rules as [`PairRecordV1`]: plain serde, no serde-with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardingRecordV1 {
    /// Lowercase 64-hex agent id.
    pub agent_id_hex: String,
    /// New relay URLs in priority order (1..=4 entries, same URL
    /// constraints as [`PairRecordV1::advertised_relays`]).
    pub moved_to_relays: Vec<String>,
    /// Millisecond timestamp at record issuance. Monotonicity is the
    /// caller's responsibility; this module does not enforce it.
    pub issued_at_ms: u64,
    /// ML-DSA-65 signature over [`forwarding_signing_input`], STANDARD
    /// base64-encoded.
    pub sig_b64: String,
}

/// A user-scoped pairing record (M6 linked devices): a user-key-signed
/// list of device agents bound under one account root.
///
/// Unlike [`PairRecordV1`] (one agent), v4 pins a `user_id` and carries
/// every device that belongs to the account. A contact verifies the user
/// signature once and pins `user_id_hex`; the device keys sign nothing
/// account-scoped. Verify with [`verify_pair_record_v4`].
///
/// # Wire representation
///
/// Plain serde; all byte fields are STANDARD base64 strings. The
/// `record_version` selector routes deserialization exactly as it does
/// for [`PairRecordV1`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairRecordV4 {
    /// Wire selector; always [`RECORD_VERSION_V4`]. Unsigned, like
    /// [`PairRecordV1::record_version`].
    #[serde(default = "default_record_version_v4")]
    pub record_version: u8,
    /// Lowercase 64-hex user id = `hex(crate::derive_user_id(pubkey))`.
    pub user_id_hex: String,
    /// Account-root ML-DSA-65 public key, STANDARD base64-encoded.
    pub user_ml_dsa_pubkey_b64: String,
    /// Monotonic revision per `user_id_hex`; a contact rejects any record
    /// whose revision is `<=` the last it accepted (anti-rollback). This
    /// stateful check is the contact's, not this stateless module's.
    pub revision: u64,
    /// Millisecond issuance timestamp; the relay logical-clock watermark.
    pub issued_at_ms: u64,
    /// The signed device list (1..=5 entries, exactly one `primary`).
    pub devices: Vec<DeviceEntryV4>,
    /// ML-DSA-65 signature by the USER key over
    /// [`pair_record_v4_signing_input`], STANDARD base64-encoded.
    pub user_signature_b64: String,
}

/// One device bound under a [`PairRecordV4`].
///
/// `ml_dsa_pubkey_b64` and `kem_pubkey_b64` are the authoritative,
/// signature-covered fields the resolve and DM-fanout path reads; that
/// path never parses the opaque `cert_b64`. The minter must keep them
/// equal to the matching fields inside the certificate so an
/// out-of-record cert presentation can never disagree with the in-record
/// device view.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEntryV4 {
    /// Lowercase 64-hex agent id = `hex(crate::derive_agent_id(pubkey))`.
    pub agent_id_hex: String,
    /// This device's ML-DSA-65 signing key, STANDARD base64-encoded.
    pub ml_dsa_pubkey_b64: String,
    /// This device's ML-KEM-768 key (the DM-fanout target), STANDARD
    /// base64-encoded.
    pub kem_pubkey_b64: String,
    /// This device's preferred relay URLs (same 1..=4 rule as V1).
    pub advertised_relays: Vec<String>,
    /// The device's `AgentCertificate`, STANDARD base64-encoded. Opaque
    /// here: bound into the record signature but not re-verified on the
    /// resolve path (it is checked when a device presents out-of-record).
    pub cert_b64: String,
    /// Millisecond certification time.
    pub added_at_ms: u64,
    /// Exactly one device in the record sets this; that device is the
    /// canonical device #1 a V1-only reader projects to.
    pub primary: bool,
}

/// Errors from pairing-record construction or verification.
#[derive(Debug, Error)]
pub enum PairRecordError {
    /// `relays` was empty (minimum is 1).
    #[error("relay list must contain at least one entry")]
    EmptyRelays,
    /// `relays` contains more than 4 entries.
    #[error("relay list has {n} entries; maximum is 4")]
    TooManyRelays {
        /// Actual relay count.
        n: usize,
    },
    /// A relay URL exceeds 256 bytes.
    #[error("relay URL is {len} bytes; maximum is 256")]
    RelayUrlTooLong {
        /// Offending URL byte length.
        len: usize,
    },
    /// A relay URL is not a valid http/https URL with a non-empty host.
    #[error("relay URL is not a valid http/https URL with a host")]
    RelayUrlInvalid,
    /// A relay URL embeds userinfo (`user:pass@`). Credentials never
    /// belong in a signed, relay-served pairing record.
    #[error("relay URL must not embed credentials")]
    RelayUrlHasCredentials,
    /// The agent id derived from the pubkey does not match the record's
    /// claimed `agent_id_hex` — the record is bound to a different
    /// identity than it claims. Distinct from [`Self::SignatureInvalid`]
    /// so defenders can tell an impersonation attempt from a malformed
    /// signature in relay logs.
    #[error("derived agent id does not match the claimed agent_id_hex")]
    AgentIdMismatch,
    /// `agent_id_hex` is not lowercase 64-hex.
    #[error("agent_id_hex must be lowercase 64-hex")]
    InvalidAgentIdHex,
    /// `user_id_hex` is not lowercase 64-hex.
    #[error("user_id_hex must be lowercase 64-hex")]
    InvalidUserIdHex,
    /// The user id derived from the account pubkey does not match the
    /// record's claimed `user_id_hex`.
    #[error("derived user id does not match the claimed user_id_hex")]
    UserIdMismatch,
    /// A v4 record carried no devices (minimum is 1).
    #[error("device list must contain at least one entry")]
    EmptyDevices,
    /// A v4 record carried more devices than the cap allows.
    #[error("device list has {n} entries; maximum is 5")]
    TooManyDevices {
        /// Actual device count.
        n: usize,
    },
    /// A v4 record did not carry exactly one primary device.
    #[error("device list must have exactly one primary device, found {n}")]
    NotExactlyOnePrimary {
        /// Number of devices flagged primary.
        n: usize,
    },
    /// A base64 field could not be decoded.
    #[error("base64 decode error: {0}")]
    Base64(String),
    /// An ML-DSA-65 public key was rejected by the backend.
    #[error("ML-DSA pubkey parse error: {0}")]
    PubkeyParse(String),
    /// An ML-DSA-65 signature was structurally invalid.
    #[error("ML-DSA signature parse error: {0}")]
    SignatureParse(String),
    /// The ML-DSA backend returned an error during verification.
    #[error("ML-DSA verify backend error: {0}")]
    VerifyBackend(String),
    /// The signature does not verify over the canonical signing input.
    #[error("signature does not verify")]
    SignatureInvalid,
    /// A field's byte length exceeds `u32::MAX`.
    #[error("field is {len} bytes; exceeds u32::MAX")]
    FieldTooLong {
        /// Offending field byte length.
        len: usize,
    },
}

/// Build the canonical signing input for a [`PairRecordV1`].
///
/// Layout (length-prefixed, `lp(x)` = `u32_be(len)` || bytes):
/// ```text
/// PAIR_RECORD_DOMAIN
/// || lp(agent_id_hex)
/// || lp(ml_dsa_pubkey raw bytes)
/// || lp(kem_pubkey raw bytes)
/// || u32_be(n_relays)
/// || lp(relay_str)*
/// || u64_be(issued_at_ms)
/// ```
///
/// `ml_dsa_pubkey` and `kem_pubkey` are the **raw bytes** (the caller
/// passes pre-decoded slices here; base64 decoding happens in
/// [`verify_pair_record`]).
///
/// All validation rules (hex format, relay count, URL validity) are
/// enforced here so unsigned garbage can never reach a signer.
///
/// # Errors
///
/// [`PairRecordError`] if any field fails validation.
pub fn pair_signing_input(
    agent_id_hex: &str,
    ml_dsa_pubkey: &[u8],
    kem_pubkey: &[u8],
    relays: &[String],
    issued_at_ms: u64,
) -> Result<Vec<u8>, PairRecordError> {
    validate_agent_id_hex(agent_id_hex)?;
    validate_relays(relays)?;

    let mut out = Vec::new();
    out.extend_from_slice(PAIR_RECORD_DOMAIN);
    push_lp(&mut out, agent_id_hex.as_bytes())?;
    push_lp(&mut out, ml_dsa_pubkey)?;
    push_lp(&mut out, kem_pubkey)?;
    let n = u32::try_from(relays.len())
        .map_err(|_| PairRecordError::TooManyRelays { n: relays.len() })?;
    out.extend_from_slice(&n.to_be_bytes());
    for relay in relays {
        push_lp(&mut out, relay.as_bytes())?;
    }
    out.extend_from_slice(&issued_at_ms.to_be_bytes());
    Ok(out)
}

/// Build the canonical signing input for a [`ForwardingRecordV1`].
///
/// Layout:
/// ```text
/// FORWARDING_DOMAIN
/// || lp(agent_id_hex)
/// || u32_be(n_relays)
/// || lp(relay_str)*
/// || u64_be(issued_at_ms)
/// ```
///
/// All validation rules are enforced here; see [`pair_signing_input`]
/// for the rationale.
///
/// # Errors
///
/// [`PairRecordError`] if any field fails validation.
pub fn forwarding_signing_input(
    agent_id_hex: &str,
    relays: &[String],
    issued_at_ms: u64,
) -> Result<Vec<u8>, PairRecordError> {
    validate_agent_id_hex(agent_id_hex)?;
    validate_relays(relays)?;

    let mut out = Vec::new();
    out.extend_from_slice(FORWARDING_DOMAIN);
    push_lp(&mut out, agent_id_hex.as_bytes())?;
    let n = u32::try_from(relays.len())
        .map_err(|_| PairRecordError::TooManyRelays { n: relays.len() })?;
    out.extend_from_slice(&n.to_be_bytes());
    for relay in relays {
        push_lp(&mut out, relay.as_bytes())?;
    }
    out.extend_from_slice(&issued_at_ms.to_be_bytes());
    Ok(out)
}

/// Verify a [`PairRecordV1`] by decoding its fields, deriving the
/// agent id from the ML-DSA-65 pubkey, reconstructing the canonical
/// signing input, and checking the ML-DSA-65 signature.
///
/// The agent id is derived from the pubkey (not trusted from the
/// `agent_id_hex` field) so a record claiming someone else's id cannot
/// pass verification.
///
/// **Watermark monotonicity** (`issued_at_ms` must be greater than the
/// previous record for this agent) is intentionally NOT checked here.
/// This function is stateless; callers that maintain per-agent watermarks
/// must enforce the anti-replay property themselves.
///
/// # Errors
///
/// [`PairRecordError`] if any decoding, derivation, or signature check
/// fails.
pub fn verify_pair_record(record: &PairRecordV1) -> Result<(), PairRecordError> {
    use saorsa_pqc::api::sig::{MlDsa, MlDsaPublicKey, MlDsaSignature, MlDsaVariant};

    // Cheap structural checks before any base64 allocation, so a
    // hostile POST with multi-megabyte fields is rejected on an O(64)
    // hex check rather than after decoding the payload.
    validate_agent_id_hex(&record.agent_id_hex)?;
    validate_relays(&record.advertised_relays)?;

    let ml_dsa_pubkey = STANDARD
        .decode(&record.ml_dsa_pubkey_b64)
        .map_err(|e| PairRecordError::Base64(e.to_string()))?;
    let kem_pubkey = STANDARD
        .decode(&record.kem_pubkey_b64)
        .map_err(|e| PairRecordError::Base64(e.to_string()))?;
    let sig_bytes = STANDARD
        .decode(&record.sig_b64)
        .map_err(|e| PairRecordError::Base64(e.to_string()))?;

    let derived_hex = hex::encode(crate::derive_agent_id(&ml_dsa_pubkey));
    if derived_hex != record.agent_id_hex {
        return Err(PairRecordError::AgentIdMismatch);
    }

    let input = pair_signing_input(
        &record.agent_id_hex,
        &ml_dsa_pubkey,
        &kem_pubkey,
        &record.advertised_relays,
        record.issued_at_ms,
    )?;

    let pk = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &ml_dsa_pubkey)
        .map_err(|e| PairRecordError::PubkeyParse(e.to_string()))?;
    let sig = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &sig_bytes)
        .map_err(|e| PairRecordError::SignatureParse(e.to_string()))?;
    let ok = MlDsa::new(MlDsaVariant::MlDsa65)
        .verify(&pk, &input, &sig)
        .map_err(|e| PairRecordError::VerifyBackend(e.to_string()))?;
    if !ok {
        return Err(PairRecordError::SignatureInvalid);
    }
    Ok(())
}

/// Verify a [`ForwardingRecordV1`] using a caller-supplied ML-DSA-65
/// pubkey.
///
/// Forwarding records carry no key material; the caller must supply the
/// agent's known pubkey (from a previously verified [`PairRecordV1`] or
/// an equivalent source). The agent id is derived from that pubkey and
/// compared to `record.agent_id_hex`; then the canonical signing input
/// is reconstructed and the signature checked.
///
/// **Watermark monotonicity** is NOT enforced here; same rationale as
/// [`verify_pair_record`].
///
/// # Errors
///
/// [`PairRecordError`] if decoding, derivation, or signature check
/// fails.
pub fn verify_forwarding_record(
    record: &ForwardingRecordV1,
    expected_pubkey: &[u8],
) -> Result<(), PairRecordError> {
    use saorsa_pqc::api::sig::{MlDsa, MlDsaPublicKey, MlDsaSignature, MlDsaVariant};

    // Cheap structural checks before the base64 allocation.
    validate_agent_id_hex(&record.agent_id_hex)?;
    validate_relays(&record.moved_to_relays)?;

    let sig_bytes = STANDARD
        .decode(&record.sig_b64)
        .map_err(|e| PairRecordError::Base64(e.to_string()))?;

    let derived_hex = hex::encode(crate::derive_agent_id(expected_pubkey));
    if derived_hex != record.agent_id_hex {
        return Err(PairRecordError::AgentIdMismatch);
    }

    let input = forwarding_signing_input(
        &record.agent_id_hex,
        &record.moved_to_relays,
        record.issued_at_ms,
    )?;

    let pk = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, expected_pubkey)
        .map_err(|e| PairRecordError::PubkeyParse(e.to_string()))?;
    let sig = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &sig_bytes)
        .map_err(|e| PairRecordError::SignatureParse(e.to_string()))?;
    let ok = MlDsa::new(MlDsaVariant::MlDsa65)
        .verify(&pk, &input, &sig)
        .map_err(|e| PairRecordError::VerifyBackend(e.to_string()))?;
    if !ok {
        return Err(PairRecordError::SignatureInvalid);
    }
    Ok(())
}

/// Pre-decoded view of one device used to build a [`PairRecordV4`] signing
/// input. Fields are raw bytes (pubkeys, cert) so the signed layout never
/// contains base64, matching [`pair_signing_input`].
pub struct DeviceSigningView<'a> {
    /// Lowercase 64-hex agent id.
    pub agent_id_hex: &'a str,
    /// Raw ML-DSA-65 device pubkey bytes.
    pub ml_dsa_pubkey: &'a [u8],
    /// Raw ML-KEM-768 device pubkey bytes.
    pub kem_pubkey: &'a [u8],
    /// Device relay URLs.
    pub relays: &'a [String],
    /// Raw `AgentCertificate` bytes.
    pub cert: &'a [u8],
    /// Certification time (ms).
    pub added_at_ms: u64,
    /// Whether this is the canonical primary device.
    pub primary: bool,
}

/// Build the canonical signing input for a [`PairRecordV4`], signed by
/// the USER key.
///
/// Layout (length-prefixed, `lp(x)` = `u32_be(len)` || bytes):
/// ```text
/// PAIR_RECORD_V4_DOMAIN
/// || lp(user_id_hex)
/// || lp(user_ml_dsa_pubkey raw)
/// || u64_be(revision)
/// || u64_be(issued_at_ms)
/// || u32_be(n_devices)
/// || for each device, in listed order:
///      lp(agent_id_hex)
///      || lp(device_ml_dsa_pubkey raw)
///      || lp(device_kem_pubkey raw)
///      || u32_be(n_relays) || lp(relay_str)*
///      || u64_be(added_at_ms)
///      || u8(primary as 0/1)
///      || lp(cert raw)
/// ```
///
/// All structural rules (hex format, device cap, exactly-one-primary,
/// relay validity) are enforced here so unsigned garbage can never reach
/// a signer.
///
/// # Errors
///
/// [`PairRecordError`] if any field or the device list fails validation.
pub fn pair_record_v4_signing_input(
    user_id_hex: &str,
    user_ml_dsa_pubkey: &[u8],
    revision: u64,
    issued_at_ms: u64,
    devices: &[DeviceSigningView<'_>],
) -> Result<Vec<u8>, PairRecordError> {
    validate_user_id_hex(user_id_hex)?;
    validate_device_list(devices)?;

    let mut out = Vec::new();
    out.extend_from_slice(PAIR_RECORD_V4_DOMAIN);
    push_lp(&mut out, user_id_hex.as_bytes())?;
    push_lp(&mut out, user_ml_dsa_pubkey)?;
    out.extend_from_slice(&revision.to_be_bytes());
    out.extend_from_slice(&issued_at_ms.to_be_bytes());
    let n = u32::try_from(devices.len())
        .map_err(|_| PairRecordError::TooManyDevices { n: devices.len() })?;
    out.extend_from_slice(&n.to_be_bytes());
    for d in devices {
        push_lp(&mut out, d.agent_id_hex.as_bytes())?;
        push_lp(&mut out, d.ml_dsa_pubkey)?;
        push_lp(&mut out, d.kem_pubkey)?;
        let rn = u32::try_from(d.relays.len())
            .map_err(|_| PairRecordError::TooManyRelays { n: d.relays.len() })?;
        out.extend_from_slice(&rn.to_be_bytes());
        for relay in d.relays {
            push_lp(&mut out, relay.as_bytes())?;
        }
        out.extend_from_slice(&d.added_at_ms.to_be_bytes());
        out.push(u8::from(d.primary));
        push_lp(&mut out, d.cert)?;
    }
    Ok(out)
}

/// Verify a [`PairRecordV4`]: check the user-id binding, each device's
/// agent-id binding, the structural rules, and the USER-key signature
/// over [`pair_record_v4_signing_input`].
///
/// The user signature authenticates the whole device list, so individual
/// `cert_b64` blobs are NOT re-verified here (they are checked only when a
/// device presents itself out-of-record). Anti-rollback on `revision` is a
/// stateful contact-side concern and is NOT enforced by this stateless
/// function.
///
/// # Errors
///
/// [`PairRecordError`] if any decode, derivation, structural, or signature
/// check fails.
pub fn verify_pair_record_v4(record: &PairRecordV4) -> Result<(), PairRecordError> {
    use saorsa_pqc::api::sig::{MlDsa, MlDsaPublicKey, MlDsaSignature, MlDsaVariant};

    // Cheap whole-list checks before any base64 allocation, so a hostile
    // record is rejected before its device blobs are decoded.
    validate_user_id_hex(&record.user_id_hex)?;
    if record.devices.is_empty() {
        return Err(PairRecordError::EmptyDevices);
    }
    if record.devices.len() > MAX_DEVICES {
        return Err(PairRecordError::TooManyDevices {
            n: record.devices.len(),
        });
    }
    let primaries = record.devices.iter().filter(|d| d.primary).count();
    if primaries != 1 {
        return Err(PairRecordError::NotExactlyOnePrimary { n: primaries });
    }

    let user_pubkey = STANDARD
        .decode(&record.user_ml_dsa_pubkey_b64)
        .map_err(|e| PairRecordError::Base64(e.to_string()))?;
    if hex::encode(crate::derive_user_id(&user_pubkey)) != record.user_id_hex {
        return Err(PairRecordError::UserIdMismatch);
    }

    // Per device: validate format, decode, check the agent-id binding.
    let mut decoded = Vec::with_capacity(record.devices.len());
    for d in &record.devices {
        validate_agent_id_hex(&d.agent_id_hex)?;
        validate_relays(&d.advertised_relays)?;
        let ml = STANDARD
            .decode(&d.ml_dsa_pubkey_b64)
            .map_err(|e| PairRecordError::Base64(e.to_string()))?;
        let kem = STANDARD
            .decode(&d.kem_pubkey_b64)
            .map_err(|e| PairRecordError::Base64(e.to_string()))?;
        let cert = STANDARD
            .decode(&d.cert_b64)
            .map_err(|e| PairRecordError::Base64(e.to_string()))?;
        if hex::encode(crate::derive_agent_id(&ml)) != d.agent_id_hex {
            return Err(PairRecordError::AgentIdMismatch);
        }
        decoded.push((ml, kem, cert));
    }

    let views: Vec<DeviceSigningView<'_>> = record
        .devices
        .iter()
        .zip(decoded.iter())
        .map(|(d, (ml, kem, cert))| DeviceSigningView {
            agent_id_hex: &d.agent_id_hex,
            ml_dsa_pubkey: ml,
            kem_pubkey: kem,
            relays: &d.advertised_relays,
            cert,
            added_at_ms: d.added_at_ms,
            primary: d.primary,
        })
        .collect();

    let input = pair_record_v4_signing_input(
        &record.user_id_hex,
        &user_pubkey,
        record.revision,
        record.issued_at_ms,
        &views,
    )?;

    let sig_bytes = STANDARD
        .decode(&record.user_signature_b64)
        .map_err(|e| PairRecordError::Base64(e.to_string()))?;
    let pk = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &user_pubkey)
        .map_err(|e| PairRecordError::PubkeyParse(e.to_string()))?;
    let sig = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &sig_bytes)
        .map_err(|e| PairRecordError::SignatureParse(e.to_string()))?;
    let ok = MlDsa::new(MlDsaVariant::MlDsa65)
        .verify(&pk, &input, &sig)
        .map_err(|e| PairRecordError::VerifyBackend(e.to_string()))?;
    if !ok {
        return Err(PairRecordError::SignatureInvalid);
    }
    Ok(())
}

fn validate_user_id_hex(s: &str) -> Result<(), PairRecordError> {
    if s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        Err(PairRecordError::InvalidUserIdHex)
    }
}

fn validate_device_list(devices: &[DeviceSigningView<'_>]) -> Result<(), PairRecordError> {
    if devices.is_empty() {
        return Err(PairRecordError::EmptyDevices);
    }
    if devices.len() > MAX_DEVICES {
        return Err(PairRecordError::TooManyDevices { n: devices.len() });
    }
    let primaries = devices.iter().filter(|d| d.primary).count();
    if primaries != 1 {
        return Err(PairRecordError::NotExactlyOnePrimary { n: primaries });
    }
    for d in devices {
        validate_agent_id_hex(d.agent_id_hex)?;
        validate_relays(d.relays)?;
    }
    Ok(())
}

fn validate_agent_id_hex(s: &str) -> Result<(), PairRecordError> {
    if s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        Err(PairRecordError::InvalidAgentIdHex)
    }
}

fn validate_relays(relays: &[String]) -> Result<(), PairRecordError> {
    if relays.is_empty() {
        return Err(PairRecordError::EmptyRelays);
    }
    if relays.len() > MAX_RELAYS {
        return Err(PairRecordError::TooManyRelays { n: relays.len() });
    }
    for relay in relays {
        if relay.len() > MAX_URL_BYTES {
            return Err(PairRecordError::RelayUrlTooLong { len: relay.len() });
        }
        let parsed = relay
            .parse::<url::Url>()
            .map_err(|_| PairRecordError::RelayUrlInvalid)?;
        let scheme = parsed.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(PairRecordError::RelayUrlInvalid);
        }
        if parsed.host_str().is_none_or(str::is_empty) {
            return Err(PairRecordError::RelayUrlInvalid);
        }
        // Credentials in a signed, relay-served URL would be handed to
        // every depositing peer's HTTP client. Reject them at the
        // signing boundary so no such record can ever be produced.
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(PairRecordError::RelayUrlHasCredentials);
        }
    }
    Ok(())
}

fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), PairRecordError> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| PairRecordError::FieldTooLong { len: bytes.len() })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const RELAY_A: &str = "https://relay-a.fetchit.io";
    const RELAY_B: &str = "https://relay-b.fetchit.io";

    fn fake_agent_hex() -> String {
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()
    }

    fn relays_one() -> Vec<String> {
        vec![RELAY_A.to_string()]
    }

    fn relays_two() -> Vec<String> {
        vec![RELAY_A.to_string(), RELAY_B.to_string()]
    }

    // -- canonical layout tests -------------------------------------------

    #[test]
    fn pair_signing_input_layout_is_canonical() {
        let agent_hex = fake_agent_hex();
        let ml_dsa_pk = [0xAA_u8, 0xBB, 0xCC];
        let kem_pk = [0x11_u8, 0x22];
        let relays = relays_one();
        let ts: u64 = 1_000_000;

        let got = pair_signing_input(&agent_hex, &ml_dsa_pk, &kem_pk, &relays, ts).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(PAIR_RECORD_DOMAIN);
        // lp(agent_id_hex)
        expected.extend_from_slice(&64u32.to_be_bytes());
        expected.extend_from_slice(agent_hex.as_bytes());
        // lp(ml_dsa_pubkey raw)
        expected.extend_from_slice(&3u32.to_be_bytes());
        expected.extend_from_slice(&ml_dsa_pk);
        // lp(kem_pubkey raw)
        expected.extend_from_slice(&2u32.to_be_bytes());
        expected.extend_from_slice(&kem_pk);
        // u32_be(n_relays)
        expected.extend_from_slice(&1u32.to_be_bytes());
        // lp(relay) — RELAY_A is 26 bytes, known at compile time
        expected.extend_from_slice(&26u32.to_be_bytes());
        expected.extend_from_slice(RELAY_A.as_bytes());
        // u64_be(issued_at_ms)
        expected.extend_from_slice(&ts.to_be_bytes());

        assert_eq!(got, expected);
    }

    #[test]
    fn forwarding_signing_input_layout_is_canonical() {
        let agent_hex = fake_agent_hex();
        let relays = relays_two();
        let ts: u64 = 2_000_000;

        let got = forwarding_signing_input(&agent_hex, &relays, ts).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(FORWARDING_DOMAIN);
        expected.extend_from_slice(&64u32.to_be_bytes());
        expected.extend_from_slice(agent_hex.as_bytes());
        expected.extend_from_slice(&2u32.to_be_bytes());
        // Both relays are 26 bytes each, known at compile time
        for relay in &relays {
            expected.extend_from_slice(&26u32.to_be_bytes());
            expected.extend_from_slice(relay.as_bytes());
        }
        expected.extend_from_slice(&ts.to_be_bytes());

        assert_eq!(got, expected);
    }

    // -- real-keypair round-trip tests ------------------------------------

    #[test]
    fn pair_record_sign_and_verify_round_trip() {
        use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};

        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let pk_bytes = pk.to_bytes();
        let agent_hex = hex::encode(crate::derive_agent_id(&pk_bytes));
        let kem_pk = vec![0x55_u8; 32];
        let relays = relays_two();
        let ts: u64 = 42;

        let input = pair_signing_input(&agent_hex, &pk_bytes, &kem_pk, &relays, ts).unwrap();
        let sig_bytes = dsa.sign(&sk, &input).unwrap().to_bytes();

        let record = PairRecordV1 {
            record_version: RECORD_VERSION_V1,
            agent_id_hex: agent_hex,
            ml_dsa_pubkey_b64: STANDARD.encode(&pk_bytes),
            kem_pubkey_b64: STANDARD.encode(&kem_pk),
            advertised_relays: relays,
            issued_at_ms: ts,
            sig_b64: STANDARD.encode(&sig_bytes),
        };

        verify_pair_record(&record).unwrap();
    }

    #[test]
    fn forwarding_record_sign_and_verify_round_trip() {
        use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};

        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let pk_bytes = pk.to_bytes();
        let agent_hex = hex::encode(crate::derive_agent_id(&pk_bytes));
        let relays = relays_one();
        let ts: u64 = 99;

        let input = forwarding_signing_input(&agent_hex, &relays, ts).unwrap();
        let sig_bytes = dsa.sign(&sk, &input).unwrap().to_bytes();

        let record = ForwardingRecordV1 {
            agent_id_hex: agent_hex,
            moved_to_relays: relays,
            issued_at_ms: ts,
            sig_b64: STANDARD.encode(&sig_bytes),
        };

        verify_forwarding_record(&record, &pk_bytes).unwrap();
    }

    // -- rejection tests --------------------------------------------------

    #[test]
    fn pair_verify_rejects_wrong_key_signature() {
        use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};

        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let (other_pk, _) = dsa.generate_keypair().unwrap();
        let pk_bytes = pk.to_bytes();
        let other_pk_bytes = other_pk.to_bytes();
        let agent_hex = hex::encode(crate::derive_agent_id(&other_pk_bytes));
        let kem_pk = vec![0x00_u8; 8];
        let relays = relays_one();
        let ts = 1u64;

        // sign with sk (key A), but embed other_pk (key B) and its derived id
        let input = pair_signing_input(&agent_hex, &other_pk_bytes, &kem_pk, &relays, ts).unwrap();
        let sig_bytes = dsa.sign(&sk, &input).unwrap().to_bytes();

        let record = PairRecordV1 {
            record_version: RECORD_VERSION_V1,
            agent_id_hex: agent_hex,
            ml_dsa_pubkey_b64: STANDARD.encode(&other_pk_bytes),
            kem_pubkey_b64: STANDARD.encode(&kem_pk),
            advertised_relays: relays.clone(),
            issued_at_ms: ts,
            sig_b64: STANDARD.encode(&sig_bytes),
        };

        // verify derives id from other_pk, id matches, but sig was made with sk not other_sk
        let err = verify_pair_record(&record).unwrap_err();
        assert!(
            matches!(err, PairRecordError::SignatureInvalid),
            "got {err:?}"
        );

        // Also verify the original pk case: sign input built for pk but claim other_pk
        let agent_hex_a = hex::encode(crate::derive_agent_id(&pk_bytes));
        let input_a = pair_signing_input(&agent_hex_a, &pk_bytes, &kem_pk, &relays, ts).unwrap();
        let sig_a = dsa.sign(&sk, &input_a).unwrap().to_bytes();
        // put wrong pubkey in record (other_pk) but same sig -- id mismatch path
        let record2 = PairRecordV1 {
            record_version: RECORD_VERSION_V1,
            agent_id_hex: agent_hex_a.clone(),
            ml_dsa_pubkey_b64: STANDARD.encode(&other_pk_bytes),
            kem_pubkey_b64: STANDARD.encode(&kem_pk),
            advertised_relays: relays.clone(),
            issued_at_ms: ts,
            sig_b64: STANDARD.encode(&sig_a),
        };
        let err2 = verify_pair_record(&record2).unwrap_err();
        // record2 embeds other_pk but claims pk's id -> binding mismatch.
        assert!(
            matches!(err2, PairRecordError::AgentIdMismatch),
            "got {err2:?}"
        );
    }

    #[test]
    fn pair_verify_rejects_derived_id_mismatch() {
        use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};

        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, signing_sk) = dsa.generate_keypair().unwrap();
        let (target_pk, _) = dsa.generate_keypair().unwrap();
        let pk_raw = pk.to_bytes();
        let target_raw = target_pk.to_bytes();
        // Use target's agent id but sign under pk's key
        let target_hex = hex::encode(crate::derive_agent_id(&target_raw));
        let kem_pk = vec![0x00_u8; 8];
        let relays = relays_one();
        let ts = 1u64;

        let input = pair_signing_input(&target_hex, &pk_raw, &kem_pk, &relays, ts).unwrap();
        let sig_bytes = dsa.sign(&signing_sk, &input).unwrap().to_bytes();

        let record = PairRecordV1 {
            record_version: RECORD_VERSION_V1,
            agent_id_hex: target_hex,
            ml_dsa_pubkey_b64: STANDARD.encode(&pk_raw),
            kem_pubkey_b64: STANDARD.encode(&kem_pk),
            advertised_relays: relays,
            issued_at_ms: ts,
            sig_b64: STANDARD.encode(&sig_bytes),
        };

        let err = verify_pair_record(&record).unwrap_err();
        // derived id from pk_raw != claimed target_hex
        assert!(
            matches!(err, PairRecordError::AgentIdMismatch),
            "got {err:?}"
        );
    }

    #[test]
    fn signing_input_rejects_empty_relays() {
        let err = pair_signing_input(&fake_agent_hex(), &[], &[], &[], 0).unwrap_err();
        assert!(matches!(err, PairRecordError::EmptyRelays));

        let err2 = forwarding_signing_input(&fake_agent_hex(), &[], 0).unwrap_err();
        assert!(matches!(err2, PairRecordError::EmptyRelays));
    }

    #[test]
    fn signing_input_rejects_five_relays() {
        let five: Vec<String> = (0..5)
            .map(|i| format!("https://r{i}.example.com"))
            .collect();
        let err = pair_signing_input(&fake_agent_hex(), &[], &[], &five, 0).unwrap_err();
        assert!(matches!(err, PairRecordError::TooManyRelays { n: 5 }));

        let err2 = forwarding_signing_input(&fake_agent_hex(), &five, 0).unwrap_err();
        assert!(matches!(err2, PairRecordError::TooManyRelays { n: 5 }));
    }

    #[test]
    fn signing_input_rejects_257_byte_relay_url() {
        // https:// (8) + 246 a's + .io (3) = 257 bytes total
        let url_257 = format!("https://{}.io", "a".repeat(246));
        assert_eq!(url_257.len(), 257);
        let relays = vec![url_257.clone()];
        let err = pair_signing_input(&fake_agent_hex(), &[], &[], &relays, 0).unwrap_err();
        assert!(
            matches!(err, PairRecordError::RelayUrlTooLong { len: 257 }),
            "got {err:?}"
        );

        let err2 = forwarding_signing_input(&fake_agent_hex(), &relays, 0).unwrap_err();
        assert!(
            matches!(err2, PairRecordError::RelayUrlTooLong { len: 257 }),
            "got {err2:?}"
        );
    }

    #[test]
    fn signing_input_rejects_file_scheme() {
        let relays = vec!["file:///etc/passwd".to_string()];
        let err = pair_signing_input(&fake_agent_hex(), &[], &[], &relays, 0).unwrap_err();
        assert!(matches!(err, PairRecordError::RelayUrlInvalid));
    }

    #[test]
    fn signing_input_rejects_missing_host() {
        // url crate rejects https with an empty host as a parse error
        let relays = vec!["https://".to_string()];
        let err = pair_signing_input(&fake_agent_hex(), &[], &[], &relays, 0).unwrap_err();
        assert!(matches!(err, PairRecordError::RelayUrlInvalid));
    }

    #[test]
    fn signing_input_rejects_uppercase_agent_hex() {
        let upper = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
        assert_eq!(upper.len(), 64);
        let err = pair_signing_input(upper, &[], &[], &relays_one(), 0).unwrap_err();
        assert!(matches!(err, PairRecordError::InvalidAgentIdHex));

        let err2 = forwarding_signing_input(upper, &relays_one(), 0).unwrap_err();
        assert!(matches!(err2, PairRecordError::InvalidAgentIdHex));
    }

    #[test]
    fn pair_record_serde_json_round_trip() {
        let record = PairRecordV1 {
            record_version: RECORD_VERSION_V1,
            agent_id_hex: fake_agent_hex(),
            ml_dsa_pubkey_b64: STANDARD.encode([0xAA_u8; 8]),
            kem_pubkey_b64: STANDARD.encode([0xBB_u8; 8]),
            advertised_relays: relays_one(),
            issued_at_ms: 12345,
            sig_b64: STANDARD.encode([0xCC_u8; 8]),
        };
        let json = serde_json::to_string(&record).unwrap();
        let recovered: PairRecordV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(record, recovered);
    }

    // -- record_version selector (M6.0) -----------------------------------

    #[test]
    fn record_version_defaults_to_one_for_legacy_json() {
        // Legacy V1 JSON predates the record_version selector; a current
        // reader must default it to RECORD_VERSION_V1 rather than fail.
        let legacy = r#"{
            "agent_id_hex":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "ml_dsa_pubkey_b64":"AAAA",
            "kem_pubkey_b64":"AAAA",
            "advertised_relays":["https://relay-a.fetchit.io"],
            "issued_at_ms":42,
            "sig_b64":"AAAA"
        }"#;
        let rec: PairRecordV1 = serde_json::from_str(legacy).unwrap();
        assert_eq!(rec.record_version, RECORD_VERSION_V1);
        assert_eq!(rec.record_version, 1);
    }

    #[test]
    fn record_version_round_trips_and_serializes() {
        let record = PairRecordV1 {
            record_version: RECORD_VERSION_V1,
            agent_id_hex: fake_agent_hex(),
            ml_dsa_pubkey_b64: STANDARD.encode([0xAA_u8; 8]),
            kem_pubkey_b64: STANDARD.encode([0xBB_u8; 8]),
            advertised_relays: relays_one(),
            issued_at_ms: 12345,
            sig_b64: STANDARD.encode([0xCC_u8; 8]),
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"record_version\":1"), "json was {json}");
        let recovered: PairRecordV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(record, recovered);
    }

    #[test]
    fn record_version_is_outside_the_signed_layout() {
        // record_version is an unsigned deserialization selector, not part
        // of the frozen canonical signing input. The authoritative version
        // binding is the domain separator inside the signature. Flipping
        // the selector on an otherwise-valid record must not invalidate it.
        use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};

        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let pk_bytes = pk.to_bytes();
        let agent_hex = hex::encode(crate::derive_agent_id(&pk_bytes));
        let kem_pk = vec![0x55_u8; 32];
        let relays = relays_one();
        let ts: u64 = 7;

        let input = pair_signing_input(&agent_hex, &pk_bytes, &kem_pk, &relays, ts).unwrap();
        let sig_bytes = dsa.sign(&sk, &input).unwrap().to_bytes();

        let record = PairRecordV1 {
            record_version: RECORD_VERSION_V1,
            agent_id_hex: agent_hex,
            ml_dsa_pubkey_b64: STANDARD.encode(&pk_bytes),
            kem_pubkey_b64: STANDARD.encode(&kem_pk),
            advertised_relays: relays,
            issued_at_ms: ts,
            sig_b64: STANDARD.encode(&sig_bytes),
        };
        verify_pair_record(&record).unwrap();

        let mut relabelled = record.clone();
        relabelled.record_version = 99;
        verify_pair_record(&relabelled).unwrap();
    }

    #[test]
    fn forwarding_record_serde_json_round_trip() {
        let record = ForwardingRecordV1 {
            agent_id_hex: fake_agent_hex(),
            moved_to_relays: relays_two(),
            issued_at_ms: 99999,
            sig_b64: STANDARD.encode([0xDD_u8; 8]),
        };
        let json = serde_json::to_string(&record).unwrap();
        let recovered: ForwardingRecordV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(record, recovered);
    }

    #[test]
    fn forwarding_verify_rejects_wrong_expected_pubkey() {
        use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};

        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let (other_pk, _) = dsa.generate_keypair().unwrap();
        let pk_bytes = pk.to_bytes();
        let other_pk_bytes = other_pk.to_bytes();
        let agent_hex = hex::encode(crate::derive_agent_id(&pk_bytes));
        let relays = relays_one();
        let ts = 7u64;

        let input = forwarding_signing_input(&agent_hex, &relays, ts).unwrap();
        let sig_bytes = dsa.sign(&sk, &input).unwrap().to_bytes();

        let record = ForwardingRecordV1 {
            agent_id_hex: agent_hex,
            moved_to_relays: relays,
            issued_at_ms: ts,
            sig_b64: STANDARD.encode(&sig_bytes),
        };

        // supply wrong pubkey -- derived id won't match
        let err = verify_forwarding_record(&record, &other_pk_bytes).unwrap_err();
        assert!(
            matches!(err, PairRecordError::AgentIdMismatch),
            "got {err:?}"
        );
    }

    #[test]
    fn signing_input_rejects_relay_with_credentials() {
        // A signed URL carrying userinfo would be handed to every
        // depositing peer's HTTP client -- reject at the signing boundary.
        let relays = vec!["https://user:secret@relay.example.com".to_string()];
        let err = pair_signing_input(&fake_agent_hex(), &[], &[], &relays, 0).unwrap_err();
        assert!(
            matches!(err, PairRecordError::RelayUrlHasCredentials),
            "got {err:?}"
        );
        let err2 = forwarding_signing_input(&fake_agent_hex(), &relays, 0).unwrap_err();
        assert!(
            matches!(err2, PairRecordError::RelayUrlHasCredentials),
            "got {err2:?}"
        );
        // Username-only (no password) is rejected too.
        let user_only = vec!["https://admin@relay.example.com".to_string()];
        let err3 = pair_signing_input(&fake_agent_hex(), &[], &[], &user_only, 0).unwrap_err();
        assert!(
            matches!(err3, PairRecordError::RelayUrlHasCredentials),
            "got {err3:?}"
        );
    }

    // -- PairRecordV4 (M6.2) ----------------------------------------------

    // (entry, ml_dsa_pubkey_raw, kem_pubkey_raw, cert_raw) for one device.
    type DeviceFixture = (DeviceEntryV4, Vec<u8>, Vec<u8>, Vec<u8>);

    fn mk_device(
        dsa: &saorsa_pqc::api::sig::MlDsa,
        kem_tag: u8,
        cert_tag: u8,
        added_at_ms: u64,
        primary: bool,
    ) -> DeviceFixture {
        let (pk, _sk) = dsa.generate_keypair().unwrap();
        let pk_b = pk.to_bytes();
        let agent = hex::encode(crate::derive_agent_id(&pk_b));
        let kem = vec![kem_tag; 32];
        let cert = vec![cert_tag; 40];
        let entry = DeviceEntryV4 {
            agent_id_hex: agent,
            ml_dsa_pubkey_b64: STANDARD.encode(&pk_b),
            kem_pubkey_b64: STANDARD.encode(&kem),
            advertised_relays: relays_one(),
            cert_b64: STANDARD.encode(&cert),
            added_at_ms,
            primary,
        };
        (entry, pk_b, kem, cert)
    }

    fn signing_views(devs: &[DeviceFixture]) -> Vec<DeviceSigningView<'_>> {
        devs.iter()
            .map(|(e, ml, kem, cert)| DeviceSigningView {
                agent_id_hex: &e.agent_id_hex,
                ml_dsa_pubkey: ml,
                kem_pubkey: kem,
                relays: &e.advertised_relays,
                cert,
                added_at_ms: e.added_at_ms,
                primary: e.primary,
            })
            .collect()
    }

    fn fake_device(agent_hex: &str, primary: bool) -> DeviceEntryV4 {
        DeviceEntryV4 {
            agent_id_hex: agent_hex.to_string(),
            ml_dsa_pubkey_b64: STANDARD.encode([0x01_u8; 8]),
            kem_pubkey_b64: STANDARD.encode([0x02_u8; 8]),
            advertised_relays: relays_one(),
            cert_b64: STANDARD.encode([0x03_u8; 8]),
            added_at_ms: 1,
            primary,
        }
    }

    fn valid_signed_v4() -> PairRecordV4 {
        use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (user_pk, user_secret) = dsa.generate_keypair().unwrap();
        let user_pk_b = user_pk.to_bytes();
        let user_id_hex = hex::encode(crate::derive_user_id(&user_pk_b));
        let devs = vec![
            mk_device(&dsa, 0x11, 0xA1, 10, true),
            mk_device(&dsa, 0x22, 0xB2, 20, false),
        ];
        let views = signing_views(&devs);
        let input = pair_record_v4_signing_input(&user_id_hex, &user_pk_b, 3, 999, &views).unwrap();
        let sig = dsa.sign(&user_secret, &input).unwrap().to_bytes();
        PairRecordV4 {
            record_version: RECORD_VERSION_V4,
            user_id_hex,
            user_ml_dsa_pubkey_b64: STANDARD.encode(&user_pk_b),
            revision: 3,
            issued_at_ms: 999,
            devices: devs.into_iter().map(|(e, ..)| e).collect(),
            user_signature_b64: STANDARD.encode(&sig),
        }
    }

    #[test]
    fn pair_record_v4_signing_input_layout_is_canonical() {
        let id_hex = "ab".repeat(32);
        let user_pk = [0xEE_u8, 0xFF];
        let dev_ml = [0x01_u8, 0x02, 0x03];
        let dev_kem = [0x04_u8];
        let cert = [0x05_u8, 0x06];
        let relays = relays_one();
        let views = vec![DeviceSigningView {
            agent_id_hex: &id_hex,
            ml_dsa_pubkey: &dev_ml,
            kem_pubkey: &dev_kem,
            relays: &relays,
            cert: &cert,
            added_at_ms: 7,
            primary: true,
        }];
        let got = pair_record_v4_signing_input(&id_hex, &user_pk, 9, 42, &views).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(PAIR_RECORD_V4_DOMAIN);
        expected.extend_from_slice(&64u32.to_be_bytes());
        expected.extend_from_slice(id_hex.as_bytes());
        expected.extend_from_slice(&2u32.to_be_bytes());
        expected.extend_from_slice(&user_pk);
        expected.extend_from_slice(&9u64.to_be_bytes());
        expected.extend_from_slice(&42u64.to_be_bytes());
        expected.extend_from_slice(&1u32.to_be_bytes()); // n_devices
        expected.extend_from_slice(&64u32.to_be_bytes());
        expected.extend_from_slice(id_hex.as_bytes());
        expected.extend_from_slice(&3u32.to_be_bytes());
        expected.extend_from_slice(&dev_ml);
        expected.extend_from_slice(&1u32.to_be_bytes());
        expected.extend_from_slice(&dev_kem);
        expected.extend_from_slice(&1u32.to_be_bytes()); // n_relays
        expected.extend_from_slice(&26u32.to_be_bytes());
        expected.extend_from_slice(RELAY_A.as_bytes());
        expected.extend_from_slice(&7u64.to_be_bytes());
        expected.push(1u8);
        expected.extend_from_slice(&2u32.to_be_bytes());
        expected.extend_from_slice(&cert);

        assert_eq!(got, expected);
    }

    #[test]
    fn pair_record_v4_sign_and_verify_round_trip() {
        verify_pair_record_v4(&valid_signed_v4()).unwrap();
    }

    #[test]
    fn v4_verify_rejects_wrong_user_key() {
        use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (user_pk, _user_sk) = dsa.generate_keypair().unwrap();
        let (_other_pk, other_sk) = dsa.generate_keypair().unwrap();
        let user_pk_b = user_pk.to_bytes();
        let user_id_hex = hex::encode(crate::derive_user_id(&user_pk_b));
        let devs = vec![mk_device(&dsa, 0x11, 0xA1, 10, true)];
        let views = signing_views(&devs);
        let input = pair_record_v4_signing_input(&user_id_hex, &user_pk_b, 1, 1, &views).unwrap();
        // Sign with a different key while embedding user_pk: the user-id
        // binding holds, but the signature is by the wrong key.
        let sig = dsa.sign(&other_sk, &input).unwrap().to_bytes();
        let record = PairRecordV4 {
            record_version: RECORD_VERSION_V4,
            user_id_hex,
            user_ml_dsa_pubkey_b64: STANDARD.encode(&user_pk_b),
            revision: 1,
            issued_at_ms: 1,
            devices: devs.into_iter().map(|(e, ..)| e).collect(),
            user_signature_b64: STANDARD.encode(&sig),
        };
        let err = verify_pair_record_v4(&record).unwrap_err();
        assert!(
            matches!(err, PairRecordError::SignatureInvalid),
            "got {err:?}"
        );
    }

    #[test]
    fn v4_verify_rejects_user_id_mismatch() {
        let mut record = valid_signed_v4();
        record.user_id_hex = "0".repeat(64);
        let err = verify_pair_record_v4(&record).unwrap_err();
        assert!(
            matches!(err, PairRecordError::UserIdMismatch),
            "got {err:?}"
        );
    }

    #[test]
    fn v4_verify_rejects_device_agent_id_mismatch() {
        let mut record = valid_signed_v4();
        record.devices[0].agent_id_hex = "a".repeat(64);
        let err = verify_pair_record_v4(&record).unwrap_err();
        assert!(
            matches!(err, PairRecordError::AgentIdMismatch),
            "got {err:?}"
        );
    }

    #[test]
    fn v4_verify_rejects_tampered_device_relay() {
        let mut record = valid_signed_v4();
        // Device pubkey unchanged (agent-id binding still holds), but the
        // relay differs from what was signed -> signature no longer covers it.
        record.devices[1].advertised_relays = vec![RELAY_B.to_string()];
        let err = verify_pair_record_v4(&record).unwrap_err();
        assert!(
            matches!(err, PairRecordError::SignatureInvalid),
            "got {err:?}"
        );
    }

    #[test]
    fn v4_verify_rejects_empty_devices() {
        let mut record = valid_signed_v4();
        record.devices.clear();
        let err = verify_pair_record_v4(&record).unwrap_err();
        assert!(matches!(err, PairRecordError::EmptyDevices), "got {err:?}");
    }

    #[test]
    fn v4_verify_rejects_too_many_devices() {
        let mut record = valid_signed_v4();
        while record.devices.len() < 6 {
            record.devices.push(fake_device(&fake_agent_hex(), false));
        }
        let err = verify_pair_record_v4(&record).unwrap_err();
        assert!(
            matches!(err, PairRecordError::TooManyDevices { n: 6 }),
            "got {err:?}"
        );
    }

    #[test]
    fn v4_verify_rejects_zero_or_two_primary() {
        let mut zero = valid_signed_v4();
        for d in &mut zero.devices {
            d.primary = false;
        }
        assert!(matches!(
            verify_pair_record_v4(&zero).unwrap_err(),
            PairRecordError::NotExactlyOnePrimary { n: 0 }
        ));

        let mut two = valid_signed_v4();
        for d in &mut two.devices {
            d.primary = true;
        }
        assert!(matches!(
            verify_pair_record_v4(&two).unwrap_err(),
            PairRecordError::NotExactlyOnePrimary { n: 2 }
        ));
    }

    #[test]
    fn pair_record_v4_serde_json_round_trip() {
        let record = valid_signed_v4();
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"record_version\":4"), "json was {json}");
        let recovered: PairRecordV4 = serde_json::from_str(&json).unwrap();
        assert_eq!(record, recovered);
    }
}
