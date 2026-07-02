//! Account fabric: the user-root key and device certificates that bind a
//! person's devices into one account (M6 linked devices).
//!
//! Each device keeps its own ML-DSA-65 agent key and its own MLS leaf;
//! what makes them one account is a **user key** the account owner holds.
//! The user key is derived deterministically from the same 32-byte root
//! seed the 24-word recovery phrase restores (`recovery_phrase` +
//! `local_signer`), under a domain separate from the device identity key
//! ([`derive_user_seed`]), so:
//!
//! - the phrase alone recovers the account root — no extra backup — and
//! - the user key is cryptographically independent of any device's agent
//!   key: compromising one device's key never yields the account key.
//!
//! The account owner mints an [`AgentCertificate`] for each device: a
//! user-key signature binding that device's agent id and keys to the
//! account [`UserKeypair::user_id_hex`]. The user id is derived via
//! [`fetchit_relay_proto::derive_user_id`] under its own
//! `fetchit-user-id-v1` domain — deliberately NOT the `AUTONOMI_PEER_ID_V2`
//! agent/peer-id domain — so an upstream peer-id bump never moves a pinned
//! account. Certificates ride opaque inside a `PairRecordV4` device entry
//! and are checked out-of-record (sibling admission, fediverse) via
//! [`verify_agent_certificate`], which mirrors `verify_pair_record_v4`'s
//! binding + signature checks.

use crate::error::ChatError;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use fetchit_relay_proto::pair_record::{
    pair_record_v4_signing_input, DeviceEntryV4, DeviceSigningView, PairRecordV4, RECORD_VERSION_V4,
};
use fetchit_relay_proto::{derive_agent_id, derive_user_id};
use hkdf::Hkdf;
use saorsa_pqc::api::sig::{MlDsa, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, MlDsaVariant};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

/// HKDF-SHA-256 `info` separating the account user key from the device
/// identity key.
///
/// **Frozen.** The derived user key — and therefore the pinned
/// `user_id` contacts anchor on — depends on this exact byte string;
/// changing it is a migration, not a patch.
pub const USER_KEY_HKDF_INFO: &[u8] = b"fetchit-user-key-v1";

/// Domain separator for [`AgentCertificate`] signing inputs.
///
/// **Frozen** wire format, mirroring `PAIR_RECORD_DOMAIN`; the version is
/// carried by the domain (not a signed field), so a future layout is a v2
/// domain, not a patch.
pub const AGENT_CERT_DOMAIN: &[u8] = b"fetchit-agent-cert-v1";

/// Current [`AgentCertificate::cert_version`] wire selector.
pub const CERT_VERSION_V1: u8 = 1;

fn default_cert_version() -> u8 {
    CERT_VERSION_V1
}

/// Derive the 32-byte account **user seed** from a device **root seed**
/// (the identity seed the recovery phrase restores).
///
/// Deterministic and domain-separated: the same root seed always yields
/// the same user seed, so the phrase recovers the account key; and the
/// HKDF `info` ([`USER_KEY_HKDF_INFO`]) makes the user seed independent
/// of the root seed and of any other key derived from it.
///
/// The returned seed is [`Zeroizing`]; feed it straight into
/// [`UserKeypair::from_seed`] and let it drop.
#[must_use]
#[allow(clippy::expect_used)]
pub fn derive_user_seed(root_seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, root_seed);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(USER_KEY_HKDF_INFO, out.as_mut())
        .expect("HKDF-SHA256 expand to 32 bytes cannot fail");
    out
}

/// The account **user keypair**: the ML-DSA-65 key the account owner holds.
///
/// Derived on demand from the account seed via [`UserKeypair::from_seed`]
/// and never persisted separately — the seed already lives in the vault,
/// so the user key is re-derived at enroll/revoke/recover and dropped.
/// Signs [`AgentCertificate`]s. Ephemeral: build it, use it, drop it.
pub struct UserKeypair {
    dsa: MlDsa,
    secret_key: MlDsaSecretKey,
    public_key_bytes: Vec<u8>,
}

impl UserKeypair {
    /// Reconstruct the user keypair deterministically from a 32-byte user
    /// seed (see [`derive_user_seed`]). Infallible, like the ML-DSA-65
    /// seeded keygen it wraps.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (public_key, secret_key) = dsa.generate_keypair_from_seed(seed);
        let public_key_bytes = public_key.to_bytes();
        Self {
            dsa,
            secret_key,
            public_key_bytes,
        }
    }

    /// The account-root ML-DSA-65 public key bytes (what contacts pin and
    /// what [`verify_agent_certificate`] verifies against).
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key_bytes
    }

    /// The account `user_id` (lowercase 64-hex) contacts pin under M6:
    /// `hex(derive_user_id(user pubkey))`, under the `fetchit-user-id-v1`
    /// domain — never the agent/peer-id domain.
    #[must_use]
    pub fn user_id_hex(&self) -> String {
        hex::encode(derive_user_id(&self.public_key_bytes))
    }

    /// Sign `message` with the user secret key (ML-DSA-65).
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, ChatError> {
        self.dsa
            .sign(&self.secret_key, message)
            .map(|s| s.to_bytes())
            .map_err(|e| ChatError::Invalid(format!("user-key sign: {e}")))
    }
}

impl std::fmt::Debug for UserKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserKeypair")
            .field("user_id_hex", &self.user_id_hex())
            .field("secret_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// A user-key signature binding one device's agent to the account
/// `user_id`.
///
/// Rides opaque (base64) inside a `PairRecordV4` device entry — bound into
/// the record signature there but not re-parsed on the resolve path — and
/// is verified out-of-record (sibling admission, fediverse) with
/// [`verify_agent_certificate`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCertificate {
    /// Unsigned wire selector; always [`CERT_VERSION_V1`]. Kept OUT of the
    /// signed input (the domain carries the version) so forward-compat
    /// dispatch never disturbs the signature.
    #[serde(default = "default_cert_version")]
    pub cert_version: u8,
    /// Account id this device belongs to: `hex(derive_user_id(user pk))`.
    pub user_id_hex: String,
    /// Device agent id: `hex(derive_agent_id(device ml-dsa pk))`.
    pub agent_id_hex: String,
    /// The device's ML-DSA-65 signing key, STANDARD base64.
    pub agent_ml_dsa_pubkey_b64: String,
    /// The device's ML-KEM-768 key (the DM-fanout target), STANDARD
    /// base64. Kept consistent with the `DeviceEntryV4` this cert rides in.
    pub kem_pubkey_b64: String,
    /// Certification time, milliseconds since Unix epoch — the same unit
    /// as the `DeviceEntryV4::added_at_ms` this cert rides beside.
    pub added_at_ms: u64,
    /// User-key ML-DSA-65 signature over [`cert_signing_input`], base64.
    pub sig_b64: String,
}

/// Length-prefix a field as `u32_be(len) || bytes`, mirroring the frozen
/// pair-record convention. (relay-proto's `push_lp` is private to that
/// crate, so this reimplements the identical layout.)
fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ChatError> {
    let n = u32::try_from(bytes.len()).map_err(|_| {
        ChatError::Invalid(format!(
            "cert field is {} bytes; exceeds u32::MAX",
            bytes.len()
        ))
    })?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Build the canonical signing input for an [`AgentCertificate`]:
/// ```text
/// AGENT_CERT_DOMAIN
/// || lp(user_id_hex) || lp(agent_id_hex)
/// || lp(agent_ml_dsa_pubkey raw) || lp(kem_pubkey raw)
/// || u64_be(added_at_ms)
/// ```
/// `lp(x)` = `u32_be(len) || bytes`. The two pubkeys are raw bytes (the
/// caller passes pre-decoded slices; base64 decode happens in
/// [`verify_agent_certificate`]).
fn cert_signing_input(
    user_id_hex: &str,
    agent_id_hex: &str,
    agent_ml_dsa_pubkey: &[u8],
    kem_pubkey: &[u8],
    added_at_ms: u64,
) -> Result<Vec<u8>, ChatError> {
    let mut out = Vec::new();
    out.extend_from_slice(AGENT_CERT_DOMAIN);
    push_lp(&mut out, user_id_hex.as_bytes())?;
    push_lp(&mut out, agent_id_hex.as_bytes())?;
    push_lp(&mut out, agent_ml_dsa_pubkey)?;
    push_lp(&mut out, kem_pubkey)?;
    out.extend_from_slice(&added_at_ms.to_be_bytes());
    Ok(out)
}

/// Mint a certificate: the account owner's [`UserKeypair`] signs a binding
/// of `agent_id_hex` and the device's keys to the account `user_id`.
///
/// `agent_ml_dsa_pubkey` and `kem_pubkey` are raw (un-encoded) bytes; the
/// caller must pass the same key bytes the device actually uses (and that
/// its `DeviceEntryV4` advertises) so the two stay consistent.
///
/// # Errors
/// [`ChatError`] if a field exceeds `u32::MAX` or the ML-DSA sign fails.
pub fn mint_agent_certificate(
    user: &UserKeypair,
    agent_id_hex: &str,
    agent_ml_dsa_pubkey: &[u8],
    kem_pubkey: &[u8],
    added_at_ms: u64,
) -> Result<AgentCertificate, ChatError> {
    // Fail fast on a minter bug: refuse to sign a cert whose agent_id does
    // not derive from the device key — such a cert could never verify
    // (mirrors relay-proto's validate-before-sign discipline).
    if hex::encode(derive_agent_id(agent_ml_dsa_pubkey)) != agent_id_hex {
        return Err(ChatError::Invalid(
            "cert agent_id does not match the device key".into(),
        ));
    }
    let user_id_hex = user.user_id_hex();
    let input = cert_signing_input(
        &user_id_hex,
        agent_id_hex,
        agent_ml_dsa_pubkey,
        kem_pubkey,
        added_at_ms,
    )?;
    let sig = user.sign(&input)?;
    Ok(AgentCertificate {
        cert_version: CERT_VERSION_V1,
        user_id_hex,
        agent_id_hex: agent_id_hex.to_owned(),
        agent_ml_dsa_pubkey_b64: B64.encode(agent_ml_dsa_pubkey),
        kem_pubkey_b64: B64.encode(kem_pubkey),
        added_at_ms,
        sig_b64: B64.encode(sig),
    })
}

/// Verify a certificate against the account's user public key.
///
/// Checks, in order (cheap bindings before the signature): the cert's
/// `user_id_hex` derives from `user_pubkey` under the user-id domain; the
/// cert's `agent_id_hex` derives from its own device pubkey; and the
/// user-key ML-DSA-65 signature verifies over the canonical input. The
/// `user_pubkey` is supplied out of band (from the pinned pair record),
/// exactly as `verify_pair_record_v4` derives the user id from the record's
/// own pubkey.
///
/// # Errors
/// [`ChatError`] on any decode, binding, or signature failure.
pub fn verify_agent_certificate(
    cert: &AgentCertificate,
    user_pubkey: &[u8],
) -> Result<(), ChatError> {
    if hex::encode(derive_user_id(user_pubkey)) != cert.user_id_hex {
        return Err(ChatError::Invalid(
            "cert user_id does not derive from the user key".into(),
        ));
    }
    let agent_ml = B64
        .decode(&cert.agent_ml_dsa_pubkey_b64)
        .map_err(|e| ChatError::Invalid(format!("cert agent pubkey b64: {e}")))?;
    let kem = B64
        .decode(&cert.kem_pubkey_b64)
        .map_err(|e| ChatError::Invalid(format!("cert kem pubkey b64: {e}")))?;
    if hex::encode(derive_agent_id(&agent_ml)) != cert.agent_id_hex {
        return Err(ChatError::Invalid(
            "cert agent_id does not derive from the device key".into(),
        ));
    }
    let input = cert_signing_input(
        &cert.user_id_hex,
        &cert.agent_id_hex,
        &agent_ml,
        &kem,
        cert.added_at_ms,
    )?;
    let sig_bytes = B64
        .decode(&cert.sig_b64)
        .map_err(|e| ChatError::Invalid(format!("cert sig b64: {e}")))?;
    let pk = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, user_pubkey)
        .map_err(|e| ChatError::Invalid(format!("user pubkey parse: {e}")))?;
    let sig = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &sig_bytes)
        .map_err(|e| ChatError::Invalid(format!("cert sig parse: {e}")))?;
    let ok = MlDsa::new(MlDsaVariant::MlDsa65)
        .verify(&pk, &input, &sig)
        .map_err(|e| ChatError::Invalid(format!("cert verify backend: {e}")))?;
    if !ok {
        return Err(ChatError::Invalid("cert signature does not verify".into()));
    }
    Ok(())
}

/// Mint a signed [`PairRecordV4`]: the account owner's [`UserKeypair`]
/// signs the canonical layout over the account user id and the device
/// list. Each device's raw pubkeys and cert are decoded from its wire
/// entry to build the signing input; the returned record is what gets
/// published to the relay and pinned by contacts.
///
/// `devices` are the wire entries, one per device, each already carrying
/// its `cert_b64` (base64 of the serialized [`AgentCertificate`], e.g. from
/// [`crate::device_cert::ensure_device_certificate`]), `ml_dsa`/`kem`
/// fields consistent with that cert, and its `primary` flag (exactly one
/// true). The structural rules (device cap, one primary, relay validity)
/// are enforced by [`pair_record_v4_signing_input`] before signing.
///
/// # Errors
/// [`ChatError`] if a device field is malformed base64, the device list
/// fails the v4 structural rules, or the ML-DSA sign fails.
pub fn mint_pair_record_v4(
    user: &UserKeypair,
    revision: u64,
    issued_at_ms: u64,
    devices: &[DeviceEntryV4],
) -> Result<PairRecordV4, ChatError> {
    // Decode each device's raw bytes for the signing view.
    let mut decoded = Vec::with_capacity(devices.len());
    for d in devices {
        let ml = B64
            .decode(&d.ml_dsa_pubkey_b64)
            .map_err(|e| ChatError::Invalid(format!("device ml_dsa b64: {e}")))?;
        let kem = B64
            .decode(&d.kem_pubkey_b64)
            .map_err(|e| ChatError::Invalid(format!("device kem b64: {e}")))?;
        let cert = B64
            .decode(&d.cert_b64)
            .map_err(|e| ChatError::Invalid(format!("device cert b64: {e}")))?;
        decoded.push((ml, kem, cert));
    }
    let views: Vec<DeviceSigningView<'_>> = devices
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

    let user_id_hex = user.user_id_hex();
    let input = pair_record_v4_signing_input(
        &user_id_hex,
        user.public_key_bytes(),
        revision,
        issued_at_ms,
        &views,
    )
    .map_err(|e| ChatError::Invalid(format!("v4 signing input: {e}")))?;
    let sig = user.sign(&input)?;

    Ok(PairRecordV4 {
        record_version: RECORD_VERSION_V4,
        user_id_hex,
        user_ml_dsa_pubkey_b64: B64.encode(user.public_key_bytes()),
        revision,
        issued_at_ms,
        devices: devices.to_vec(),
        user_signature_b64: B64.encode(sig),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn user_seed_derives_deterministically_from_root() {
        let root = [7u8; 32];
        assert_eq!(*derive_user_seed(&root), *derive_user_seed(&root));
    }

    #[test]
    fn user_seed_is_domain_separated_from_root() {
        // The account key must never equal the device identity key it is
        // derived from — that separation is the whole point of the HKDF.
        let root = [7u8; 32];
        assert_ne!(*derive_user_seed(&root), root);
    }

    #[test]
    fn distinct_roots_yield_distinct_user_seeds() {
        assert_ne!(*derive_user_seed(&[1u8; 32]), *derive_user_seed(&[2u8; 32]));
    }

    #[test]
    fn user_key_derives_deterministically_from_seed() {
        let seed = [3u8; 32];
        let a = UserKeypair::from_seed(&seed);
        let b = UserKeypair::from_seed(&seed);
        assert_eq!(a.public_key_bytes(), b.public_key_bytes());
        assert_eq!(a.user_id_hex(), b.user_id_hex());
        assert_eq!(a.user_id_hex().len(), 64);
    }

    #[test]
    fn mint_rejects_unbound_agent_id() {
        // mint fails fast when agent_id does not derive from the device
        // key, so a minter bug cannot produce a cert that would only fail
        // later at verify (matches relay-proto's validate-before-sign).
        use fetchit_relay_client::{MlDsaSigner, Signer};
        let user = UserKeypair::from_seed(&[5u8; 32]);
        let device = MlDsaSigner::from_seed(&[9u8; 32]);
        let unbound = "ab".repeat(32);
        let result =
            mint_agent_certificate(&user, &unbound, &device.public_key(), &[0x22; 64], 1_000);
        assert!(result.is_err());
    }

    // Build a cert whose agent_id_hex correctly binds its device key, so
    // the happy path and each tamper can be asserted precisely.
    fn bound_cert() -> (UserKeypair, Vec<u8>, AgentCertificate) {
        use fetchit_relay_client::{MlDsaSigner, Signer};
        let user = UserKeypair::from_seed(&[8u8; 32]);
        let device = MlDsaSigner::from_seed(&[9u8; 32]);
        let agent_id_hex = hex::encode(device.agent_id());
        let cert = mint_agent_certificate(
            &user,
            &agent_id_hex,
            &device.public_key(),
            &[0x42; 64],
            1_700_000_000,
        )
        .unwrap();
        (user, device.public_key(), cert)
    }

    #[test]
    fn bound_cert_roundtrip_verifies() {
        let (user, _device_pk, cert) = bound_cert();
        verify_agent_certificate(&cert, user.public_key_bytes()).unwrap();
    }

    #[test]
    fn cert_rejects_tampered_agent_id() {
        let (user, _device_pk, mut cert) = bound_cert();
        cert.agent_id_hex = "cd".repeat(32);
        assert!(verify_agent_certificate(&cert, user.public_key_bytes()).is_err());
    }

    #[test]
    fn cert_rejects_wrong_user_key() {
        let (_user, _device_pk, cert) = bound_cert();
        let other = UserKeypair::from_seed(&[123u8; 32]);
        assert!(verify_agent_certificate(&cert, other.public_key_bytes()).is_err());
    }

    #[test]
    fn cert_rejects_tampered_kem() {
        // kem is not part of the agent-id binding but IS in the signing
        // input, so flipping it must break the signature.
        let (user, _device_pk, mut cert) = bound_cert();
        cert.kem_pubkey_b64 = B64.encode([0x99; 64]);
        assert!(verify_agent_certificate(&cert, user.public_key_bytes()).is_err());
    }

    #[test]
    fn existing_phrase_reroots_to_user_key_without_changing_agent_id() {
        use fetchit_relay_client::{MlDsaSigner, Signer};
        // The 32-byte seed a recovery phrase restores drives the device
        // agent key today.
        let root = [9u8; 32];
        let agent = MlDsaSigner::from_seed(&root);
        let agent_id_before = hex::encode(agent.agent_id());

        // Re-root: derive the account user key from the SAME seed — a
        // distinct key under a distinct domain, so user_id != agent_id.
        let user = UserKeypair::from_seed(&derive_user_seed(&root));
        assert_ne!(user.user_id_hex(), agent_id_before);

        // The account owner self-certifies the existing device #1.
        let cert = mint_agent_certificate(
            &user,
            &agent_id_before,
            &agent.public_key(),
            &[0x42; 64],
            1_000,
        )
        .unwrap();
        verify_agent_certificate(&cert, user.public_key_bytes()).unwrap();

        // Re-deriving the agent from the same seed yields the same agent
        // id: the re-root never disturbs the device identity.
        let agent_again = MlDsaSigner::from_seed(&root);
        assert_eq!(hex::encode(agent_again.agent_id()), agent_id_before);
    }

    #[test]
    fn mint_pair_record_v4_produces_a_verifiable_record() {
        use fetchit_relay_proto::pair_record::verify_pair_record_v4;
        // A bound device + its cert (kem and added_at sourced from the cert
        // so the record and cert stay consistent).
        let (user, device_pk, cert) = bound_cert();
        let device = DeviceEntryV4 {
            agent_id_hex: cert.agent_id_hex.clone(),
            ml_dsa_pubkey_b64: B64.encode(&device_pk),
            kem_pubkey_b64: cert.kem_pubkey_b64.clone(),
            advertised_relays: vec!["https://relay.example".to_string()],
            cert_b64: B64.encode(serde_json::to_vec(&cert).unwrap()),
            added_at_ms: cert.added_at_ms,
            primary: true,
        };

        let record = mint_pair_record_v4(&user, 1, 1234, &[device]).unwrap();

        verify_pair_record_v4(&record).unwrap();
        assert_eq!(record.revision, 1);
        assert_eq!(record.user_id_hex, user.user_id_hex());
    }
}
