//! Signing helpers and logical-clock watermark store for pairing records.
//!
//! Two concerns live here:
//!
//! **(A) Record builders** — assemble and sign [`PairRecordV1`] and
//! [`ForwardingRecordV1`] using the local chat [`FetchitIdentity`] and
//! [`Signer`].
//!
//! **(B) Logical-clock watermark** — [`next_issued_at_ms`] returns a
//! monotonically increasing millisecond timestamp even if the wall clock
//! moves backward (battery reset, VM snapshot). The returned value is
//! persisted immediately so the guarantee holds across process restarts.

use crate::chat_identity::FetchitIdentity;
use crate::error::{ChatError, Result};
use crate::local_store::StoreLayout;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use fetchit_relay_client::Signer;
use fetchit_relay_proto::pair_record::{
    forwarding_signing_input, pair_signing_input, ForwardingRecordV1, PairRecordV1,
};
use std::collections::BTreeMap;
use std::sync::Mutex;

// ── (A) Record builders ───────────────────────────────────────────────────────

/// Build and sign a [`PairRecordV1`] from the local identity and signer.
///
/// The `agent_id_hex`, ML-DSA-65 pubkey (via `signer.public_key()`), and
/// ML-KEM-768 pubkey (via `identity.kem_public_key()`) are read from the
/// canonical sources so they can never drift from the rest of the crate.
///
/// # Errors
///
/// [`ChatError::Invalid`] if [`pair_signing_input`] rejects any field or
/// if the signer returns an error.
pub async fn build_signed_pair_record(
    identity: &FetchitIdentity,
    signer: &dyn Signer,
    advertised_relays: Vec<String>,
    issued_at_ms: u64,
) -> Result<PairRecordV1> {
    let agent_id_hex = identity.agent_id_hex().to_owned();
    let ml_dsa_pubkey = signer.public_key();
    let kem_pubkey = identity.kem_public_key();

    let input = pair_signing_input(
        &agent_id_hex,
        &ml_dsa_pubkey,
        kem_pubkey,
        &advertised_relays,
        issued_at_ms,
    )
    .map_err(|e| ChatError::Invalid(format!("pair_signing_input: {e}")))?;

    let sig = signer
        .sign(&input)
        .await
        .map_err(|e| ChatError::Invalid(format!("ml-dsa sign: {e}")))?;

    Ok(PairRecordV1 {
        agent_id_hex,
        ml_dsa_pubkey_b64: STANDARD.encode(&ml_dsa_pubkey),
        kem_pubkey_b64: STANDARD.encode(kem_pubkey),
        advertised_relays,
        issued_at_ms,
        sig_b64: STANDARD.encode(&sig),
    })
}

/// Build and sign a [`ForwardingRecordV1`] from the local identity and signer.
///
/// # Errors
///
/// [`ChatError::Invalid`] if [`forwarding_signing_input`] rejects any field
/// or if the signer returns an error.
pub async fn build_signed_forwarding_record(
    identity: &FetchitIdentity,
    signer: &dyn Signer,
    moved_to_relays: Vec<String>,
    issued_at_ms: u64,
) -> Result<ForwardingRecordV1> {
    let agent_id_hex = identity.agent_id_hex().to_owned();
    let ml_dsa_pubkey = signer.public_key();

    let input = forwarding_signing_input(&agent_id_hex, &moved_to_relays, issued_at_ms)
        .map_err(|e| ChatError::Invalid(format!("forwarding_signing_input: {e}")))?;

    let sig = signer
        .sign(&input)
        .await
        .map_err(|e| ChatError::Invalid(format!("ml-dsa sign: {e}")))?;

    // `ml_dsa_pubkey` is not part of the forwarding record wire format but
    // is consumed above; binding it here keeps the borrow alive past `sign`.
    let _ = &ml_dsa_pubkey;

    Ok(ForwardingRecordV1 {
        agent_id_hex,
        moved_to_relays,
        issued_at_ms,
        sig_b64: STANDARD.encode(&sig),
    })
}

// ── (B) Logical-clock watermark ───────────────────────────────────────────────

const WATERMARK_FILE: &str = "pair_record_watermarks.json";

/// Serialises read-modify-write so concurrent calls for the same or
/// different agents don't clobber each other's entry. The clock-backward
/// brick fix depends on atomicity here.
static WATERMARK_LOCK: Mutex<()> = Mutex::new(());

fn watermark_path(layout: &StoreLayout) -> std::path::PathBuf {
    layout.root.join(WATERMARK_FILE)
}

/// Return the next monotonically increasing millisecond timestamp for
/// `self_agent_hex`, then persist it so the guarantee holds across
/// process restarts and wall-clock steps backward.
///
/// Returns `max(wall_clock_ms, last_stored + 1)` when a prior value
/// exists, or `wall_clock_ms` on first call. The returned value is the
/// new high-water mark. The write is atomic (temp + rename) so a crash
/// mid-write cannot corrupt the file.
///
/// # Errors
///
/// [`ChatError::Io`] if the watermark file cannot be written.
pub fn next_issued_at_ms(
    layout: &StoreLayout,
    self_agent_hex: &str,
    wall_clock_ms: u64,
) -> Result<u64> {
    let _guard = WATERMARK_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let path = watermark_path(layout);
    let mut map: BTreeMap<String, u64> = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();

    let last = map.get(self_agent_hex).copied().unwrap_or(0);
    // Monotonic clock: never go back, even if the wall clock does.
    let next = if last > 0 {
        wall_clock_ms.max(last + 1)
    } else {
        wall_clock_ms
    };

    map.insert(self_agent_hex.to_owned(), next);

    let bytes = serde_json::to_vec(&map)
        .map_err(|e| ChatError::Invalid(format!("watermark serialize: {e}")))?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, &path)?;

    Ok(next)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use fetchit_relay_client::MlDsaSigner;
    use tempfile::tempdir;

    const RELAY_A: &str = "https://relay-a.fetchit.io";

    fn relays() -> Vec<String> {
        vec![RELAY_A.to_owned()]
    }

    // Build a minimal FetchitIdentity for unit testing by constructing one
    // through the real vault path so we never touch private fields.
    fn make_identity(dir: &std::path::Path, agent_id_hex: &str) -> FetchitIdentity {
        use crate::at_rest::{fresh_argon_salt, kdf_id_argon2, MasterKey, MasterKeySource};
        use zeroize::Zeroizing;
        let salt = fresh_argon_salt();
        let master = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("pw".into())),
            Some(&salt),
        )
        .unwrap();
        FetchitIdentity::load_or_create(dir, &master, agent_id_hex, kdf_id_argon2(), Some(&salt))
            .unwrap()
    }

    fn make_signer() -> MlDsaSigner {
        MlDsaSigner::generate().unwrap()
    }

    // Derive an agent_id_hex that matches a real MlDsaSigner so
    // verify_pair_record's agent-id binding check passes.
    fn agent_hex_for(signer: &MlDsaSigner) -> String {
        use fetchit_relay_proto::derive_agent_id;
        hex::encode(derive_agent_id(&signer.public_key()))
    }

    // ── (A) pair-record builders ──────────────────────────────────────────────

    #[tokio::test]
    async fn build_signed_pair_record_round_trips_verify() {
        let dir = tempdir().unwrap();
        let signer = make_signer();
        let agent_hex = agent_hex_for(&signer);
        let identity = make_identity(dir.path(), &agent_hex);

        let record = build_signed_pair_record(&identity, &signer, relays(), 1_000_000)
            .await
            .unwrap();

        assert_eq!(record.agent_id_hex, agent_hex);
        assert_eq!(record.issued_at_ms, 1_000_000);

        fetchit_relay_proto::pair_record::verify_pair_record(&record)
            .expect("built record must verify");
    }

    #[tokio::test]
    async fn build_signed_forwarding_record_verifies() {
        let dir = tempdir().unwrap();
        let signer = make_signer();
        let agent_hex = agent_hex_for(&signer);
        let identity = make_identity(dir.path(), &agent_hex);
        let pubkey = signer.public_key();

        let record = build_signed_forwarding_record(&identity, &signer, relays(), 2_000_000)
            .await
            .unwrap();

        assert_eq!(record.agent_id_hex, agent_hex);
        fetchit_relay_proto::pair_record::verify_forwarding_record(&record, &pubkey)
            .expect("built forwarding record must verify");
    }

    #[tokio::test]
    async fn build_pair_record_empty_relays_returns_error() {
        let dir = tempdir().unwrap();
        let signer = make_signer();
        let agent_hex = agent_hex_for(&signer);
        let identity = make_identity(dir.path(), &agent_hex);

        let err = build_signed_pair_record(&identity, &signer, vec![], 1)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("pair_signing_input"), "got {err}");
    }

    #[tokio::test]
    async fn build_forwarding_record_empty_relays_returns_error() {
        let dir = tempdir().unwrap();
        let signer = make_signer();
        let agent_hex = agent_hex_for(&signer);
        let identity = make_identity(dir.path(), &agent_hex);

        let err = build_signed_forwarding_record(&identity, &signer, vec![], 1)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("forwarding_signing_input"),
            "got {err}"
        );
    }

    // ── (B) watermark store ───────────────────────────────────────────────────

    fn make_layout(dir: &std::path::Path) -> StoreLayout {
        StoreLayout::ensure(dir.to_path_buf()).unwrap()
    }

    const AGENT: &str = "aabbccdd00000000000000000000000000000000000000000000000000001234";

    #[test]
    fn watermark_fresh_store_seeds_from_wall_clock() {
        let dir = tempdir().unwrap();
        let layout = make_layout(dir.path());
        let got = next_issued_at_ms(&layout, AGENT, 5_000).unwrap();
        assert_eq!(got, 5_000);
    }

    #[test]
    fn watermark_monotonic_across_same_wall_clock() {
        let dir = tempdir().unwrap();
        let layout = make_layout(dir.path());
        let a = next_issued_at_ms(&layout, AGENT, 1_000).unwrap();
        let b = next_issued_at_ms(&layout, AGENT, 1_000).unwrap();
        assert!(
            b > a,
            "second call with same wall clock must advance: {a} -> {b}"
        );
    }

    #[test]
    fn watermark_clock_backward_still_increases() {
        let dir = tempdir().unwrap();
        let layout = make_layout(dir.path());
        let a = next_issued_at_ms(&layout, AGENT, 1_000).unwrap();
        let b = next_issued_at_ms(&layout, AGENT, 500).unwrap();
        assert!(
            b > a,
            "clock step backward must still increase watermark: {a} -> {b}"
        );
    }

    #[test]
    fn watermark_persists_across_reload() {
        let dir = tempdir().unwrap();
        let layout = make_layout(dir.path());
        let first = next_issued_at_ms(&layout, AGENT, 9_000).unwrap();
        // Simulate a process restart by calling again on the same layout.
        // The persisted file is re-read; the watermark must not regress.
        let second = next_issued_at_ms(&layout, AGENT, 9_000).unwrap();
        assert!(
            second > first,
            "re-read persisted value must advance monotonically: {first} -> {second}"
        );
    }

    #[test]
    fn watermark_per_agent_isolation() {
        let dir = tempdir().unwrap();
        let layout = make_layout(dir.path());
        let agent_b = "bbbbccdd00000000000000000000000000000000000000000000000000001234";

        next_issued_at_ms(&layout, AGENT, 10_000).unwrap();
        // A different agent starting from 0 should seed from its own wall clock.
        let b = next_issued_at_ms(&layout, agent_b, 1).unwrap();
        assert_eq!(b, 1, "different agent must start from its own wall clock");
    }
}
