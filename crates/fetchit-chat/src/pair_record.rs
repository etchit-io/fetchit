//! Signing helpers and logical-clock watermark store for pairing records.
//!
//! Three concerns live here:
//!
//! **(A) Record builders** — assemble and sign [`PairRecordV1`] and
//! [`ForwardingRecordV1`] using the local chat [`FetchitIdentity`] and
//! [`Signer`].
//!
//! **(B) Logical-clock watermark** — [`next_issued_at_ms`] returns a
//! monotonically increasing millisecond timestamp even if the wall clock
//! moves backward (battery reset, VM snapshot). The returned value is
//! persisted immediately so the guarantee holds across process restarts.
//!
//! **(C) HTTP publish:** `post_pair_record` / `post_forwarding_record`
//! publish signed records to a relay, handling the 409 clock-bump retry
//! and the 412 non-fatal skip.

use crate::chat_identity::FetchitIdentity;
use crate::error::{ChatError, Result};
use crate::local_store::StoreLayout;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use fetchit_relay_client::Signer;
use fetchit_relay_proto::pair_record::{
    forwarding_signing_input, pair_signing_input, ForwardingRecordV1, PairRecordV1,
};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

// ── (A) Record builders ───────────────────────────────────────────────────────

/// Normalize a relay URL to the http/https form the pair-record and
/// forwarding-record signing inputs require.
///
/// Advertised relays and v2 rendezvous hints carry the `wss://` (or `ws://`)
/// transport form peers dial directly. The signed pair-record / forwarding-record
/// `relays` field is, by contract, the relay's HTTP endpoint (peers upgrade to
/// `wss://` at connect via [`fetchit_relay_client`]'s WS-URL builder), and
/// [`pair_signing_input`] / [`forwarding_signing_input`] reject any non-http/https
/// scheme. So a wss-default client (whose primary relay is `wss://…`) would fail
/// to publish unless the list is mapped to its HTTP form right here, at the
/// signing boundary.
///
/// The mapping is `wss → https` and `ws → http`; http/https inputs (and any other
/// scheme, which the signing input rejects downstream regardless) pass through
/// unchanged, so calling this on an already-http/https list is a no-op. Only the
/// scheme is touched: host, port, and path are preserved.
fn relays_to_http_for_signing(relays: &[String]) -> Vec<String> {
    relays
        .iter()
        .map(|relay| {
            let Ok(mut url) = relay.parse::<url::Url>() else {
                return relay.clone();
            };
            let mapped = match url.scheme() {
                "wss" => "https",
                "ws" => "http",
                // http/https (and anything else, which the signing input
                // rejects) pass through untouched.
                _ => return relay.clone(),
            };
            if url.set_scheme(mapped).is_err() {
                return relay.clone();
            }
            url.to_string()
        })
        .collect()
}

/// Build and sign a [`PairRecordV1`] from the local identity and signer.
///
/// The `agent_id_hex`, ML-DSA-65 pubkey (via `signer.public_key()`), and
/// ML-KEM-768 pubkey (via `identity.kem_public_key()`) are read from the
/// canonical sources so they can never drift from the rest of the crate.
///
/// `advertised_relays` may arrive in `wss://` / `ws://` transport form (the
/// shape advertised to peers); it is normalized to the http/https form the
/// signing input requires via [`relays_to_http_for_signing`] before signing.
/// The returned record's `advertised_relays` carries that normalized form,
/// matching the bytes actually signed.
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
    ensure_identity_binds_signer(&agent_id_hex, &ml_dsa_pubkey)?;

    let advertised_relays = relays_to_http_for_signing(&advertised_relays);

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
        record_version: fetchit_relay_proto::pair_record::RECORD_VERSION_V1,
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
/// `moved_to_relays` may arrive in `wss://` / `ws://` transport form; it is
/// normalized to the http/https form the signing input requires via
/// [`relays_to_http_for_signing`] before signing, and the returned record
/// carries that normalized form.
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
    ensure_identity_binds_signer(&agent_id_hex, &ml_dsa_pubkey)?;

    let moved_to_relays = relays_to_http_for_signing(&moved_to_relays);

    let input = forwarding_signing_input(&agent_id_hex, &moved_to_relays, issued_at_ms)
        .map_err(|e| ChatError::Invalid(format!("forwarding_signing_input: {e}")))?;

    let sig = signer
        .sign(&input)
        .await
        .map_err(|e| ChatError::Invalid(format!("ml-dsa sign: {e}")))?;

    Ok(ForwardingRecordV1 {
        agent_id_hex,
        moved_to_relays,
        issued_at_ms,
        sig_b64: STANDARD.encode(&sig),
    })
}

/// Fail loudly when the identity's `agent_id_hex` is not the id derived
/// from the signer's pubkey. Without this a mis-wired (identity, signer)
/// pair silently produces a record that every relay rejects with
/// `AgentIdMismatch` -- a confusing remote failure for a local bug.
fn ensure_identity_binds_signer(agent_id_hex: &str, ml_dsa_pubkey: &[u8]) -> Result<()> {
    let derived = hex::encode(fetchit_relay_proto::derive_agent_id(ml_dsa_pubkey));
    if derived == agent_id_hex {
        Ok(())
    } else {
        Err(ChatError::Invalid(format!(
            "identity agent_id_hex does not match signer-derived id (derived {derived})"
        )))
    }
}

// ── (C) HTTP publish ─────────────────────────────────────────────────────────

/// Upper bound on a relay response body we will buffer. Pair records and
/// 409 bodies are a few KB; this stops a hostile relay from streaming an
/// unbounded body to OOM the client.
pub(crate) const MAX_RELAY_BODY_BYTES: usize = 64 * 1024;

/// Outcome of a single `POST /v1/pair-record` attempt.
#[derive(Debug)]
pub enum PostOutcome {
    /// The relay accepted the record (2xx).
    Accepted,
    /// The relay rejected with 409 Conflict: our `issued_at_ms` was not
    /// strictly greater than the relay's stored watermark. The relay body
    /// carries the value we must exceed on a retry.
    WatermarkReject {
        /// The relay's current stored `issued_at_ms` for this agent.
        current_issued_at_ms: u64,
    },
}

/// 409 response body from the relay's watermark guard.
#[derive(Deserialize)]
struct WatermarkRejectBody {
    current_issued_at_ms: u64,
}

/// `POST <relay>/v1/pair-record` with a 10-second timeout.
///
/// - 2xx → [`PostOutcome::Accepted`].
/// - 409 → parse the `{"current_issued_at_ms": N}` body →
///   [`PostOutcome::WatermarkReject`].
/// - Any other non-2xx → [`ChatError::Invalid`] with the status code.
///
/// # Errors
///
/// [`ChatError::Transport`] on connection failure, or
/// [`ChatError::Invalid`] for non-2xx (other than 409).
pub async fn post_pair_record(
    relay: &url::Url,
    record: &PairRecordV1,
    http: &reqwest::Client,
) -> Result<PostOutcome> {
    crate::relay_http::guard_relay_url(relay)
        .await
        .map_err(|e| ChatError::Invalid(format!("relay blocked: {e}")))?;
    let url = relay
        .join("v1/pair-record")
        .map_err(|e| ChatError::Invalid(format!("build relay url: {e}")))?;
    let resp = crate::relay_http::relay_send_with_retry(|| {
        http.post(url.clone())
            .json(record)
            .timeout(Duration::from_secs(10))
    })
    .await?;
    let status = resp.status();
    if status.is_success() {
        return Ok(PostOutcome::Accepted);
    }
    if status.as_u16() == 409 {
        // The real 409 body is a few bytes of JSON; the cap guards a
        // hostile/buggy relay.
        let raw = crate::relay_http::read_body_capped(resp, MAX_RELAY_BODY_BYTES)
            .await
            .map_err(|e| ChatError::Invalid(e.to_string()))?;
        let body: WatermarkRejectBody = serde_json::from_slice(&raw)
            .map_err(|e| ChatError::Invalid(format!("409 body decode: {e}")))?;
        return Ok(PostOutcome::WatermarkReject {
            current_issued_at_ms: body.current_issued_at_ms,
        });
    }
    Err(ChatError::Invalid(format!(
        "relay returned {s} publishing pair record",
        s = status.as_u16()
    )))
}

/// Outcome returned by [`post_forwarding_record`].
#[derive(Debug)]
pub enum ForwardingOutcome {
    /// The relay accepted the forwarding record (2xx).
    Written,
    /// The relay returned 412 Precondition Failed: no pair-record exists
    /// for this agent at the old relay. Non-fatal: the migration still
    /// succeeds via the next stale hint or the new relays directly.
    SkippedNoPairRecord,
}

/// Internal single-attempt result, including the 409 sentinel.
enum ForwardingAttempt {
    Written,
    SkippedNoPairRecord,
    WatermarkReject { current_issued_at_ms: u64 },
}

/// `POST <relay>/v1/forwarding` once, returning the raw attempt outcome.
async fn post_forwarding_once(
    relay: &url::Url,
    record: &fetchit_relay_proto::pair_record::ForwardingRecordV1,
    http: &reqwest::Client,
) -> Result<ForwardingAttempt> {
    crate::relay_http::guard_relay_url(relay)
        .await
        .map_err(|e| ChatError::Invalid(format!("relay blocked: {e}")))?;
    let url = relay
        .join("v1/forwarding")
        .map_err(|e| ChatError::Invalid(format!("build relay url: {e}")))?;
    let resp = crate::relay_http::relay_send_with_retry(|| {
        http.post(url.clone())
            .json(record)
            .timeout(std::time::Duration::from_secs(10))
    })
    .await?;
    let status = resp.status();
    if status.is_success() {
        return Ok(ForwardingAttempt::Written);
    }
    if status.as_u16() == 409 {
        let raw = crate::relay_http::read_body_capped(resp, MAX_RELAY_BODY_BYTES)
            .await
            .map_err(|e| ChatError::Invalid(e.to_string()))?;
        let body: WatermarkRejectBody = serde_json::from_slice(&raw)
            .map_err(|e| ChatError::Invalid(format!("409 body decode: {e}")))?;
        return Ok(ForwardingAttempt::WatermarkReject {
            current_issued_at_ms: body.current_issued_at_ms,
        });
    }
    if status.as_u16() == 412 {
        return Ok(ForwardingAttempt::SkippedNoPairRecord);
    }
    if status.as_u16() == 403 {
        return Err(ChatError::Invalid(format!(
            "relay rejected forwarding record with 403 (bad sig) at {relay}"
        )));
    }
    Err(ChatError::Invalid(format!(
        "relay returned {s} publishing forwarding record",
        s = status.as_u16()
    )))
}

/// Build, sign, and `POST <relay>/v1/forwarding` with clock-bump retry.
///
/// Handles the TB2 contract Option A response set:
/// - 2xx -> [`ForwardingOutcome::Written`].
/// - 409 -> observe the relay's watermark, re-sign with a fresh
///   `issued_at_ms`, and retry ONCE. A second 409 is a hard error.
/// - 412 -> [`ForwardingOutcome::SkippedNoPairRecord`] (non-fatal: old
///   relay has no pair-record for this agent, so the guard cannot apply;
///   log and skip, the migration still succeeds).
/// - 403 -> [`ChatError::Invalid`] (bad sig; should not happen for our
///   own records).
/// - Other non-2xx -> [`ChatError::Invalid`] with the status code.
///
/// # Errors
///
/// [`ChatError::Transport`] on connection failure.
/// [`ChatError::Invalid`] for a second 409, 403, or other non-2xx.
pub async fn post_forwarding_record(
    relay: &url::Url,
    identity: &crate::chat_identity::FetchitIdentity,
    signer: &dyn fetchit_relay_client::Signer,
    moved_to_relays: Vec<String>,
    layout: &crate::local_store::StoreLayout,
    http: &reqwest::Client,
) -> Result<ForwardingOutcome> {
    let agent_hex = identity.agent_id_hex().to_owned();
    let wall_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0));
    let issued = next_issued_at_ms(layout, &agent_hex, wall_ms)?;
    let record = build_signed_forwarding_record(identity, signer, moved_to_relays, issued).await?;

    match post_forwarding_once(relay, &record, http).await? {
        ForwardingAttempt::Written => Ok(ForwardingOutcome::Written),
        ForwardingAttempt::SkippedNoPairRecord => {
            log::warn!(
                "[chat] forwarding record: relay at {relay} has no pair-record for {}; skipping (non-fatal)",
                &agent_hex[..8],
            );
            Ok(ForwardingOutcome::SkippedNoPairRecord)
        }
        ForwardingAttempt::WatermarkReject {
            current_issued_at_ms,
        } => {
            observe_external_watermark(layout, &agent_hex, current_issued_at_ms)?;
            let wall_ms2 = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0));
            let issued2 = next_issued_at_ms(layout, &agent_hex, wall_ms2)?;
            let record2 =
                build_signed_forwarding_record(identity, signer, record.moved_to_relays, issued2)
                    .await?;
            match post_forwarding_once(relay, &record2, http).await? {
                ForwardingAttempt::Written => Ok(ForwardingOutcome::Written),
                ForwardingAttempt::SkippedNoPairRecord => {
                    log::warn!(
                        "[chat] forwarding record retry: relay at {relay} has no pair-record; skipping",
                    );
                    Ok(ForwardingOutcome::SkippedNoPairRecord)
                }
                ForwardingAttempt::WatermarkReject { .. } => Err(ChatError::Invalid(
                    "forwarding record publish rejected twice by relay watermark guard".into(),
                )),
            }
        }
    }
}

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
    // A stored watermark at u64::MAX is corrupt state (~584 million years
    // past epoch, unreachable legitimately): refuse rather than hand out a
    // duplicate or wrap to a smaller value that would let a relay reject
    // the agent forever.
    if last == u64::MAX {
        return Err(ChatError::Invalid(
            "pair-record watermark is corrupt (u64::MAX)".into(),
        ));
    }
    // Logical monotonic clock: never regress, even when the wall clock
    // does (battery reset, VM snapshot) or is 0 (first call must still
    // advance past a prior 0). saturating_add is defense-in-depth; the
    // guard above already rules out the only overflowing input.
    let next = wall_clock_ms.max(last.saturating_add(1));
    // Never persist the corrupt sentinel, regardless of how `next` got
    // there (a u64::MAX wall clock, or last == MAX-1). This keeps any
    // future caller from bricking publishing by passing a bad wall clock,
    // independent of the call-site fallback discipline.
    if next == u64::MAX {
        return Err(ChatError::Invalid(
            "pair-record watermark would reach u64::MAX (corrupt clock input)".into(),
        ));
    }

    map.insert(self_agent_hex.to_owned(), next);

    let bytes = serde_json::to_vec(&map)
        .map_err(|e| ChatError::Invalid(format!("watermark serialize: {e}")))?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, &path)?;

    Ok(next)
}

/// Peek the current watermark for `self_agent_hex` without advancing it.
///
/// Returns the last value stored by [`next_issued_at_ms`] for this agent,
/// or `None` when no record exists yet (never published). No write,
/// no bump — callers that need a monotonically-increasing timestamp for
/// a new publish must use [`next_issued_at_ms`] instead.
///
/// # Errors
///
/// [`ChatError::Io`] if the watermark file exists but cannot be read.
pub fn current_watermark(layout: &StoreLayout, self_agent_hex: &str) -> Result<Option<u64>> {
    let _guard = WATERMARK_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let path = watermark_path(layout);
    let map: BTreeMap<String, u64> = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();

    Ok(map.get(self_agent_hex).copied())
}

/// Record an externally-observed `issued_at_ms` value for
/// `self_agent_hex`, setting the stored watermark to
/// `max(stored, observed_ms)`.
///
/// This is used by the 409-retry path in
/// [`crate::client::Client::publish_pair_record`]: when the relay
/// rejects our record because our `issued_at_ms` was not strictly
/// greater than its stored value, we observe its current value here so
/// the subsequent call to [`next_issued_at_ms`] returns `observed + 1`.
///
/// Refuses to store `u64::MAX` (same corrupt-guard as
/// [`next_issued_at_ms`]). If the current stored watermark already
/// exceeds or equals `observed_ms`, this is a no-op.
///
/// # Errors
///
/// [`ChatError::Io`] if the watermark file cannot be written, or
/// [`ChatError::Invalid`] if `observed_ms == u64::MAX`.
pub fn observe_external_watermark(
    layout: &StoreLayout,
    self_agent_hex: &str,
    observed_ms: u64,
) -> Result<()> {
    if observed_ms == u64::MAX {
        return Err(ChatError::Invalid(
            "pair-record watermark is corrupt (u64::MAX)".into(),
        ));
    }

    let _guard = WATERMARK_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let path = watermark_path(layout);
    let mut map: BTreeMap<String, u64> = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();

    let stored = map.get(self_agent_hex).copied().unwrap_or(0);
    if observed_ms <= stored {
        return Ok(());
    }

    map.insert(self_agent_hex.to_owned(), observed_ms);
    let bytes = serde_json::to_vec(&map)
        .map_err(|e| ChatError::Invalid(format!("watermark serialize: {e}")))?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
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

    // ── (A) wss/ws relay normalization at the signing boundary ────────────────

    #[test]
    fn relays_to_http_for_signing_maps_wss_and_ws() {
        let got = relays_to_http_for_signing(&[
            "wss://nyc-relay.etchit.io/v1/ws".to_owned(),
            "ws://10.0.0.1:8088/v1/ws".to_owned(),
        ]);
        assert_eq!(
            got,
            vec![
                "https://nyc-relay.etchit.io/v1/ws".to_owned(),
                "http://10.0.0.1:8088/v1/ws".to_owned(),
            ]
        );
    }

    #[test]
    fn relays_to_http_for_signing_is_idempotent_on_http_https() {
        let input = vec![
            "https://relay.example.com".to_owned(),
            "http://67.207.94.66:8088".to_owned(),
        ];
        // http/https pass through unchanged, and a second pass is a no-op.
        let once = relays_to_http_for_signing(&input);
        assert_eq!(once, input);
        assert_eq!(relays_to_http_for_signing(&once), input);
    }

    #[tokio::test]
    async fn build_signed_pair_record_normalizes_wss_to_https() {
        let dir = tempdir().unwrap();
        let signer = make_signer();
        let agent_hex = agent_hex_for(&signer);
        let identity = make_identity(dir.path(), &agent_hex);

        // A wss-default client feeds a wss:// relay list. It must sign with
        // the https form (pair_signing_input rejects wss) and the record
        // must verify -- i.e. the signed bytes match the normalized relays.
        let record = build_signed_pair_record(
            &identity,
            &signer,
            vec!["wss://nyc-relay.etchit.io/v1/ws".to_owned()],
            1_000_000,
        )
        .await
        .unwrap();

        assert_eq!(
            record.advertised_relays,
            vec!["https://nyc-relay.etchit.io/v1/ws".to_owned()],
            "wss must be normalized to https in the signed record"
        );
        fetchit_relay_proto::pair_record::verify_pair_record(&record)
            .expect("normalized record must verify");
    }

    #[tokio::test]
    async fn build_signed_forwarding_record_normalizes_ws_to_http() {
        let dir = tempdir().unwrap();
        let signer = make_signer();
        let agent_hex = agent_hex_for(&signer);
        let identity = make_identity(dir.path(), &agent_hex);
        let pubkey = signer.public_key();

        let record = build_signed_forwarding_record(
            &identity,
            &signer,
            vec!["ws://relay.example.com:8088/v1/ws".to_owned()],
            2_000_000,
        )
        .await
        .unwrap();

        assert_eq!(
            record.moved_to_relays,
            vec!["http://relay.example.com:8088/v1/ws".to_owned()],
            "ws must be normalized to http in the signed forwarding record"
        );
        fetchit_relay_proto::pair_record::verify_forwarding_record(&record, &pubkey)
            .expect("normalized record must verify");
    }

    #[tokio::test]
    async fn build_signed_pair_record_leaves_https_untouched() {
        let dir = tempdir().unwrap();
        let signer = make_signer();
        let agent_hex = agent_hex_for(&signer);
        let identity = make_identity(dir.path(), &agent_hex);

        // An already-http/https list (the legacy bare-IP form) must round-trip
        // byte-for-byte: normalization is idempotent here.
        let record = build_signed_pair_record(&identity, &signer, relays(), 3_000_000)
            .await
            .unwrap();
        assert_eq!(record.advertised_relays, relays());
        fetchit_relay_proto::pair_record::verify_pair_record(&record)
            .expect("https record must verify");
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
    fn watermark_wall_clock_zero_first_call_advances_past_zero() {
        // Regression: a first call at wall=0 must NOT return 0 (a second
        // wall=0 call would then duplicate it and a strict-greater relay
        // would reject the second record).
        let dir = tempdir().unwrap();
        let layout = make_layout(dir.path());
        let got = next_issued_at_ms(&layout, AGENT, 0).unwrap();
        assert!(got > 0, "wall=0 first call must advance past 0, got {got}");
    }

    #[test]
    fn watermark_wall_clock_max_input_errors_not_bricks() {
        // A u64::MAX wall clock (overflow fallback) must error rather than
        // persist the corrupt sentinel and brick all future publishes.
        let dir = tempdir().unwrap();
        let layout = make_layout(dir.path());
        let err = next_issued_at_ms(&layout, AGENT, u64::MAX).unwrap_err();
        assert!(err.to_string().contains("corrupt"), "got {err}");
        // And a normal call afterward still works (nothing corrupt persisted).
        let ok = next_issued_at_ms(&layout, AGENT, 5_000).unwrap();
        assert_eq!(ok, 5_000);
    }

    #[test]
    fn watermark_corrupt_max_returns_error_not_panic() {
        // A persisted u64::MAX is corrupt; the call must error rather than
        // panic (debug overflow), wrap (release), or hand out a duplicate.
        let dir = tempdir().unwrap();
        let layout = make_layout(dir.path());
        let mut map: BTreeMap<String, u64> = BTreeMap::new();
        map.insert(AGENT.to_owned(), u64::MAX);
        std::fs::write(watermark_path(&layout), serde_json::to_vec(&map).unwrap()).unwrap();

        let err = next_issued_at_ms(&layout, AGENT, 1_000).unwrap_err();
        assert!(err.to_string().contains("corrupt"), "got {err}");
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

    // ── (B) current_watermark peek ───────────────────────────────────────────

    #[test]
    fn current_watermark_returns_none_on_fresh_store() {
        let dir = tempdir().unwrap();
        let layout = make_layout(dir.path());
        assert_eq!(current_watermark(&layout, AGENT).unwrap(), None);
    }

    #[test]
    fn current_watermark_returns_value_after_bump_without_bumping_itself() {
        let dir = tempdir().unwrap();
        let layout = make_layout(dir.path());
        let bumped = next_issued_at_ms(&layout, AGENT, 7_000).unwrap();
        // Peek must equal the bumped value.
        assert_eq!(current_watermark(&layout, AGENT).unwrap(), Some(bumped));
        // Calling current_watermark again must NOT advance the stored value.
        assert_eq!(current_watermark(&layout, AGENT).unwrap(), Some(bumped));
        // A subsequent next_issued_at_ms must advance past bumped.
        let next = next_issued_at_ms(&layout, AGENT, 7_000).unwrap();
        assert!(
            next > bumped,
            "next_issued_at_ms must advance past peek value: {bumped} -> {next}"
        );
        // Peek now reflects the new high-water mark, not the pre-peek value.
        assert_eq!(current_watermark(&layout, AGENT).unwrap(), Some(next));
    }

    // ── (B) observe_external_watermark ───────────────────────────────────────

    #[test]
    fn observe_external_watermark_bumps_next_past_observed() {
        let dir = tempdir().unwrap();
        let layout = make_layout(dir.path());
        let observed: u64 = 50_000;
        observe_external_watermark(&layout, AGENT, observed).unwrap();
        // next_issued_at_ms must return > observed
        let next = next_issued_at_ms(&layout, AGENT, 1).unwrap();
        assert!(
            next > observed,
            "next_issued_at_ms must exceed observed watermark {observed}, got {next}"
        );
    }

    #[test]
    fn observe_external_watermark_is_monotonic() {
        let dir = tempdir().unwrap();
        let layout = make_layout(dir.path());
        // Seed a high watermark.
        next_issued_at_ms(&layout, AGENT, 100_000).unwrap();
        // Observing a lower value must not regress the stored watermark.
        observe_external_watermark(&layout, AGENT, 1_000).unwrap();
        let next = next_issued_at_ms(&layout, AGENT, 1).unwrap();
        assert!(
            next > 100_000,
            "lower observe must not regress stored watermark; got {next}"
        );
    }

    #[test]
    fn observe_external_watermark_rejects_max() {
        let dir = tempdir().unwrap();
        let layout = make_layout(dir.path());
        let err = observe_external_watermark(&layout, AGENT, u64::MAX).unwrap_err();
        assert!(err.to_string().contains("corrupt"), "got {err}");
    }

    #[test]
    fn observe_then_next_with_wall_zero_exceeds_observed() {
        // The 409-retry contract: after observing the relay's watermark,
        // the next issued_at must be strictly greater than it even when the
        // wall clock reads 0.
        let dir = tempdir().unwrap();
        let layout = make_layout(dir.path());
        observe_external_watermark(&layout, AGENT, 1_000).unwrap();
        let next = next_issued_at_ms(&layout, AGENT, 0).unwrap();
        assert!(next > 1_000, "next must exceed observed 1000, got {next}");
    }

    #[test]
    fn observe_near_ceiling_then_next_hits_corrupt_guard() {
        // Observe u64::MAX - 1, then next_issued_at_ms with wall 0 computes
        // (MAX-1)+1 == MAX and must error on the corrupt-sentinel guard
        // rather than persist u64::MAX and brick future publishes.
        let dir = tempdir().unwrap();
        let layout = make_layout(dir.path());
        observe_external_watermark(&layout, AGENT, u64::MAX - 1).unwrap();
        let err = next_issued_at_ms(&layout, AGENT, 0).unwrap_err();
        assert!(err.to_string().contains("corrupt"), "got {err}");
        // The corrupt sentinel was never persisted: the stored value is the
        // observed MAX-1, not MAX.
        assert_eq!(
            current_watermark(&layout, AGENT).unwrap(),
            Some(u64::MAX - 1)
        );
    }

    // ── (C) post_pair_record wiremock ─────────────────────────────────────────

    /// Helper: build a valid `PairRecordV1` using a fresh ML-DSA-65 keypair.
    async fn build_test_pair_record(
        relays: Vec<String>,
        issued_at_ms: u64,
    ) -> (PairRecordV1, fetchit_relay_client::MlDsaSigner) {
        use crate::at_rest::{fresh_argon_salt, kdf_id_argon2, MasterKey, MasterKeySource};
        use zeroize::Zeroizing;

        let dir = tempdir().unwrap();
        let salt = fresh_argon_salt();
        let master = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("pw".into())),
            Some(&salt),
        )
        .unwrap();
        let signer = make_signer();
        let agent_hex = agent_hex_for(&signer);
        let identity = FetchitIdentity::load_or_create(
            dir.path(),
            &master,
            &agent_hex,
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();
        let record = build_signed_pair_record(&identity, &signer, relays, issued_at_ms)
            .await
            .unwrap();
        (record, signer)
    }

    #[tokio::test]
    async fn post_pair_record_accepted_on_200() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let (record, _) =
            build_test_pair_record(vec!["https://relay.example.com".to_owned()], 1_000).await;
        let relay = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let http = reqwest::Client::new();
        match post_pair_record(&relay, &record, &http).await.unwrap() {
            PostOutcome::Accepted => {}
            other @ PostOutcome::WatermarkReject { .. } => {
                panic!("expected Accepted, got {other:?}")
            }
        }
    }

    #[tokio::test]
    async fn post_pair_record_watermark_reject_on_409() {
        use serde_json::json;
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(409)
                    .set_body_json(json!({"current_issued_at_ms": 99_999u64})),
            )
            .mount(&server)
            .await;

        let (record, _) =
            build_test_pair_record(vec!["https://relay.example.com".to_owned()], 1_000).await;
        let relay = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let http = reqwest::Client::new();
        match post_pair_record(&relay, &record, &http).await.unwrap() {
            PostOutcome::WatermarkReject {
                current_issued_at_ms,
            } => {
                assert_eq!(current_issued_at_ms, 99_999);
            }
            other @ PostOutcome::Accepted => panic!("expected WatermarkReject, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn post_pair_record_error_on_other_non_2xx() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let (record, _) =
            build_test_pair_record(vec!["https://relay.example.com".to_owned()], 1_000).await;
        let relay = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let http = reqwest::Client::new();
        match post_pair_record(&relay, &record, &http).await {
            Err(e) => assert!(e.to_string().contains("500"), "got {e}"),
            Ok(o) => panic!("expected Err, got {o:?}"),
        }
    }

    // ── (D) post_forwarding_record wiremock ───────────────────────────────────

    fn build_test_forwarding_ctx() -> (
        FetchitIdentity,
        fetchit_relay_client::MlDsaSigner,
        StoreLayout,
    ) {
        use crate::at_rest::{fresh_argon_salt, kdf_id_argon2, MasterKey, MasterKeySource};
        use zeroize::Zeroizing;

        let dir = tempdir().unwrap();
        let salt = fresh_argon_salt();
        let master = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("pw".into())),
            Some(&salt),
        )
        .unwrap();
        let signer = make_signer();
        let agent_hex = agent_hex_for(&signer);
        let identity = FetchitIdentity::load_or_create(
            dir.path(),
            &master,
            &agent_hex,
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();
        let layout = StoreLayout::ensure(dir.keep()).unwrap();
        (identity, signer, layout)
    }

    #[tokio::test]
    async fn post_forwarding_record_written_on_200() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let (identity, signer, layout) = build_test_forwarding_ctx();
        let relay = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let http = reqwest::Client::new();
        let moved = vec!["https://new-relay.example.com".to_owned()];
        match post_forwarding_record(&relay, &identity, &signer, moved, &layout, &http)
            .await
            .unwrap()
        {
            ForwardingOutcome::Written => {}
            other @ ForwardingOutcome::SkippedNoPairRecord => {
                panic!("expected Written, got {other:?}")
            }
        }
    }

    #[tokio::test]
    async fn post_forwarding_record_skipped_on_412() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(412))
            .mount(&server)
            .await;

        let (identity, signer, layout) = build_test_forwarding_ctx();
        let relay = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let http = reqwest::Client::new();
        let moved = vec!["https://new-relay.example.com".to_owned()];
        // 412 is non-fatal: must return Ok(SkippedNoPairRecord), not Err.
        match post_forwarding_record(&relay, &identity, &signer, moved, &layout, &http)
            .await
            .unwrap()
        {
            ForwardingOutcome::SkippedNoPairRecord => {}
            other @ ForwardingOutcome::Written => {
                panic!("expected SkippedNoPairRecord, got {other:?}")
            }
        }
    }

    #[tokio::test]
    async fn post_forwarding_record_bump_retry_on_409_then_written() {
        use serde_json::json;
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // First call: 409 with a watermark value higher than the initial issued_at.
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(409)
                    .set_body_json(json!({"current_issued_at_ms": 999_999u64})),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        // Retry: 200.
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let (identity, signer, layout) = build_test_forwarding_ctx();
        let relay = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let http = reqwest::Client::new();
        let moved = vec!["https://new-relay.example.com".to_owned()];
        match post_forwarding_record(&relay, &identity, &signer, moved, &layout, &http)
            .await
            .unwrap()
        {
            ForwardingOutcome::Written => {}
            other @ ForwardingOutcome::SkippedNoPairRecord => {
                panic!("expected Written after 409+retry, got {other:?}")
            }
        }
    }

    #[tokio::test]
    async fn post_forwarding_record_403_returns_err() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let (identity, signer, layout) = build_test_forwarding_ctx();
        let relay = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let http = reqwest::Client::new();
        let moved = vec!["https://new-relay.example.com".to_owned()];
        match post_forwarding_record(&relay, &identity, &signer, moved, &layout, &http).await {
            Err(e) => assert!(
                e.to_string().contains("403"),
                "error must mention 403, got {e}"
            ),
            Ok(o) => panic!("expected Err on 403, got {o:?}"),
        }
    }

    #[tokio::test]
    async fn post_pair_record_409_empty_body_is_decode_error() {
        use serde_json::json;
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // 409 whose body lacks current_issued_at_ms must surface a decode
        // error, never a silent WatermarkReject with a default value.
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(409).set_body_json(json!({})))
            .mount(&server)
            .await;

        let (record, _) =
            build_test_pair_record(vec!["https://relay.example.com".to_owned()], 1_000).await;
        let relay = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let http = reqwest::Client::new();
        match post_pair_record(&relay, &record, &http).await {
            Err(e) => assert!(e.to_string().contains("decode"), "got {e}"),
            Ok(o) => panic!("expected decode error, got {o:?}"),
        }
    }

    #[tokio::test]
    async fn post_forwarding_record_409_twice_errors_rejected_twice() {
        use serde_json::json;
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Both the initial POST and the bump-retry get 409: the second 409
        // is a hard error, not an infinite retry.
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(409)
                    .set_body_json(json!({"current_issued_at_ms": 999_999u64})),
            )
            .mount(&server)
            .await;

        let (identity, signer, layout) = build_test_forwarding_ctx();
        let relay = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let http = reqwest::Client::new();
        let moved = vec!["https://new-relay.example.com".to_owned()];
        match post_forwarding_record(&relay, &identity, &signer, moved, &layout, &http).await {
            Err(e) => assert!(e.to_string().contains("rejected twice"), "got {e}"),
            Ok(o) => panic!("expected rejected-twice error, got {o:?}"),
        }
    }

    #[tokio::test]
    async fn post_forwarding_record_409_then_412_skips() {
        use serde_json::json;
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // First POST: 409 with a watermark to bump past.
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(409)
                    .set_body_json(json!({"current_issued_at_ms": 999_999u64})),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        // Retry: 412 (old relay has no pair-record) -> non-fatal skip.
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(412))
            .mount(&server)
            .await;

        let (identity, signer, layout) = build_test_forwarding_ctx();
        let relay = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let http = reqwest::Client::new();
        let moved = vec!["https://new-relay.example.com".to_owned()];
        match post_forwarding_record(&relay, &identity, &signer, moved, &layout, &http)
            .await
            .unwrap()
        {
            ForwardingOutcome::SkippedNoPairRecord => {}
            other @ ForwardingOutcome::Written => {
                panic!("expected SkippedNoPairRecord after 409+412, got {other:?}")
            }
        }
    }
}
