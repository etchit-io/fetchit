//! Framed Noise XX over an async byte stream — building block for
//! [`crate::lan_direct_transport`].
//!
//! Two layers:
//! 1. Plain Noise XX (`run_initiator_plain` / `run_responder_plain`) —
//!    just `snow` over the wire, no application payload. Useful as a
//!    fixture and for incremental TDD.
//! 2. Bound Noise XX (`run_initiator_bound` / `run_responder_bound`) —
//!    carries an [`crate::chat_crypto::lan_binding_bytes`]-shaped
//!    ML-DSA-65 signature on handshake messages 2 and 3, binding the
//!    X25519 static identity to the `agent_id` that the contact card
//!    already authenticates. Returns the verified peer `agent_id`.
//!
//! Wire framing post-handshake is `u32 BE length prefix || ciphertext`,
//! capped at [`MAX_FRAME`] (65 535) bytes.

use crate::chat_crypto::{lan_binding_bytes, ml_dsa_verify};
use crate::error::ChatError;
use serde::{Deserialize, Serialize};
use snow::{Builder, HandshakeState, TransportState};
use std::future::Future;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Hard cap on a single framed ciphertext, including the AEAD tag.
pub const MAX_FRAME: usize = 65_535;

/// snow's Noise pattern string for the v1 LAN handshake.
pub const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Largest handshake message we'll send/receive (snow's per-message
/// limit is 65 535).
const HANDSHAKE_MSG_CAP: usize = 65_535;

/// Run the plain (no application-layer auth) initiator half of XX.
///
/// # Errors
/// I/O or snow handshake errors.
pub async fn run_initiator_plain<S>(
    stream: &mut S,
    prologue: &[u8],
    static_sec: &[u8; 32],
) -> Result<TransportState, ChatError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut hs = build_xx(true, prologue, static_sec)?;
    // -> e
    let mut buf = vec![0u8; HANDSHAKE_MSG_CAP];
    let len = hs.write_message(&[], &mut buf).map_err(snow_err)?;
    write_frame_raw(stream, &buf[..len]).await?;
    // <- e, ee, s, es
    let msg = read_frame_raw(stream).await?;
    let mut tmp = vec![0u8; HANDSHAKE_MSG_CAP];
    let _ = hs.read_message(&msg, &mut tmp).map_err(snow_err)?;
    // -> s, se
    let len = hs.write_message(&[], &mut buf).map_err(snow_err)?;
    write_frame_raw(stream, &buf[..len]).await?;
    hs.into_transport_mode().map_err(snow_err)
}

/// Run the plain responder half of XX.
///
/// # Errors
/// I/O or snow handshake errors.
pub async fn run_responder_plain<S>(
    stream: &mut S,
    prologue: &[u8],
    static_sec: &[u8; 32],
) -> Result<TransportState, ChatError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut hs = build_xx(false, prologue, static_sec)?;
    let mut tmp = vec![0u8; HANDSHAKE_MSG_CAP];
    // <- e
    let msg = read_frame_raw(stream).await?;
    let _ = hs.read_message(&msg, &mut tmp).map_err(snow_err)?;
    // -> e, ee, s, es
    let mut buf = vec![0u8; HANDSHAKE_MSG_CAP];
    let len = hs.write_message(&[], &mut buf).map_err(snow_err)?;
    write_frame_raw(stream, &buf[..len]).await?;
    // <- s, se
    let msg = read_frame_raw(stream).await?;
    let _ = hs.read_message(&msg, &mut tmp).map_err(snow_err)?;
    hs.into_transport_mode().map_err(snow_err)
}

/// Build an XX handshake state from a raw 32-byte X25519 static secret.
fn build_xx(
    initiator: bool,
    prologue: &[u8],
    static_sec: &[u8; 32],
) -> Result<HandshakeState, ChatError> {
    let params: snow::params::NoiseParams = NOISE_PARAMS
        .parse()
        .map_err(|e: snow::Error| ChatError::Invalid(format!("snow params: {e}")))?;
    let builder = Builder::new(params)
        .local_private_key(static_sec)
        .map_err(snow_err)?
        .prologue(prologue)
        .map_err(snow_err)?;
    if initiator {
        builder.build_initiator().map_err(snow_err)
    } else {
        builder.build_responder().map_err(snow_err)
    }
}

#[allow(clippy::needless_pass_by_value)]
fn snow_err(e: snow::Error) -> ChatError {
    // Taken by value so the function works as a `.map_err(snow_err)`
    // callback — clippy's reference suggestion breaks that usage.
    ChatError::Invalid(format!("snow: {e}"))
}

// ── Framing ────────────────────────────────────────────────────────────

/// Write one length-prefixed frame to the stream. Caller-supplied buffer
/// must already be ciphertext (or a handshake message); the prefix is
/// `u32 BE` so callers don't need a second byte order in the noise
/// transport.
async fn write_frame_raw<W>(w: &mut W, body: &[u8]) -> Result<(), ChatError>
where
    W: AsyncWrite + Unpin,
{
    if body.len() > MAX_FRAME {
        return Err(ChatError::Invalid(format!(
            "lan frame {} exceeds cap {}",
            body.len(),
            MAX_FRAME
        )));
    }
    let len_u32 = u32::try_from(body.len())
        .map_err(|_| ChatError::Invalid("frame length overflow".into()))?;
    w.write_all(&len_u32.to_be_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await?;
    Ok(())
}

async fn read_frame_raw<R>(r: &mut R) -> Result<Vec<u8>, ChatError>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(ChatError::Invalid(format!(
            "inbound lan frame {len} exceeds cap {MAX_FRAME}"
        )));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(body)
}

/// Write one application-layer plaintext through `ts`, framed.
///
/// # Errors
/// I/O, framing-cap, or AEAD encryption errors.
pub async fn write_app_frame<W>(
    w: &mut W,
    ts: &mut TransportState,
    plaintext: &[u8],
) -> Result<(), ChatError>
where
    W: AsyncWrite + Unpin,
{
    let mut ct = vec![0u8; plaintext.len() + 16];
    let len = ts.write_message(plaintext, &mut ct).map_err(snow_err)?;
    write_frame_raw(w, &ct[..len]).await
}

// ── Channel-binding XX (msg2 + msg3 carry an ML-DSA signature) ───────

/// Wire shape of the binding payload carried in XX msg2 and msg3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanBindingProof {
    /// Signer's `agent_id` (32 bytes, raw).
    pub agent_id: [u8; 32],
    /// Signer's X25519 static public key (32 bytes).
    pub x25519_pub: [u8; 32],
    /// `created_at_ms` from the [`crate::lan_static::LanStaticIdentity`]
    /// that owns the X25519 keypair. Bound into the signed bytes; not
    /// trusted as a freshness clock yet.
    pub created_at_ms: u64,
    /// ML-DSA-65 signature over
    /// `lan_binding_bytes(agent_id, x25519_pub, created_at_ms) ||
    ///  handshake_hash_at_signing_time`.
    pub sig: Vec<u8>,
}

/// Returned by the bound handshake — what the verifier learned about
/// the peer. The `peer_static_pub` is recovered from snow's
/// `get_remote_static()` after the handshake completes and cross-
/// checked against the signed binding.
#[derive(Debug, Clone)]
pub struct VerifiedPeer {
    /// Peer `agent_id` proven via prologue + ML-DSA signature.
    pub agent_id: [u8; 32],
    /// Peer's X25519 static public key as recovered from snow.
    pub x25519_pub: [u8; 32],
    /// `created_at_ms` from the peer's binding.
    pub created_at_ms: u64,
}

/// Initiator side of the channel-binding XX handshake.
///
/// `sign_blob` is invoked once with the bytes to sign; production
/// callers wire it to [`fetchit_relay_client::Signer::sign`] so the
/// ML-DSA-65 secret stays inside x0xd. `peer_pubkey_lookup` looks up
/// the ML-DSA public key for the advertised peer `agent_id`; missing
/// entries abort the handshake before any signature verification runs.
///
/// # Errors
/// I/O, snow handshake, serialization, or signature-verification errors.
#[allow(clippy::too_many_arguments)] // factoring into a struct hides the seam the desktop wires
pub async fn run_initiator_bound<S, F, Fut>(
    stream: &mut S,
    prologue: &[u8],
    my_static_sec: &[u8; 32],
    my_agent_id: &[u8; 32],
    my_x25519_pub: &[u8; 32],
    my_created_at_ms: u64,
    sign_blob: F,
    peer_pubkey_lookup: &(dyn Fn(&[u8; 32]) -> Option<Vec<u8>> + Sync),
) -> Result<(TransportState, VerifiedPeer), ChatError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(Vec<u8>) -> Fut,
    Fut: Future<Output = Result<Vec<u8>, ChatError>>,
{
    let mut hs = build_xx(true, prologue, my_static_sec)?;
    let mut buf = vec![0u8; HANDSHAKE_MSG_CAP];
    let mut tmp = vec![0u8; HANDSHAKE_MSG_CAP];

    // -> e
    let len = hs.write_message(&[], &mut buf).map_err(snow_err)?;
    write_frame_raw(stream, &buf[..len]).await?;

    // h-snapshot at the moment the responder will sign (== current
    // initiator-side h before read_message of msg2).
    let h_at_responder_sign = hs.get_handshake_hash().to_vec();

    // <- e, ee, s, es + responder binding payload
    let msg2 = read_frame_raw(stream).await?;
    let payload_len = hs.read_message(&msg2, &mut tmp).map_err(snow_err)?;
    let peer_proof: LanBindingProof = postcard::from_bytes(&tmp[..payload_len])
        .map_err(|e| ChatError::Invalid(format!("lan binding decode: {e}")))?;
    verify_peer_binding(&hs, &peer_proof, &h_at_responder_sign, peer_pubkey_lookup)?;

    // h-snapshot at the moment we sign (== h after reading msg2).
    let h_at_self_sign = hs.get_handshake_hash().to_vec();
    let to_sign = bind_signing_bytes(
        my_agent_id,
        my_x25519_pub,
        my_created_at_ms,
        &h_at_self_sign,
    );
    let sig = sign_blob(to_sign).await?;
    let my_proof = LanBindingProof {
        agent_id: *my_agent_id,
        x25519_pub: *my_x25519_pub,
        created_at_ms: my_created_at_ms,
        sig,
    };
    let payload = postcard::to_allocvec(&my_proof)
        .map_err(|e| ChatError::Invalid(format!("lan binding encode: {e}")))?;

    // -> s, se + initiator binding payload
    let len = hs.write_message(&payload, &mut buf).map_err(snow_err)?;
    write_frame_raw(stream, &buf[..len]).await?;

    let ts = hs.into_transport_mode().map_err(snow_err)?;
    Ok((
        ts,
        VerifiedPeer {
            agent_id: peer_proof.agent_id,
            x25519_pub: peer_proof.x25519_pub,
            created_at_ms: peer_proof.created_at_ms,
        },
    ))
}

/// Responder side of the channel-binding XX handshake. See
/// [`run_initiator_bound`] for the `sign_blob` / `peer_pubkey_lookup`
/// contract.
///
/// # Errors
/// I/O, snow handshake, serialization, or signature-verification errors.
#[allow(clippy::too_many_arguments)] // mirrors `run_initiator_bound`
pub async fn run_responder_bound<S, F, Fut>(
    stream: &mut S,
    prologue: &[u8],
    my_static_sec: &[u8; 32],
    my_agent_id: &[u8; 32],
    my_x25519_pub: &[u8; 32],
    my_created_at_ms: u64,
    sign_blob: F,
    peer_pubkey_lookup: &(dyn Fn(&[u8; 32]) -> Option<Vec<u8>> + Sync),
) -> Result<(TransportState, VerifiedPeer), ChatError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(Vec<u8>) -> Fut,
    Fut: Future<Output = Result<Vec<u8>, ChatError>>,
{
    let mut hs = build_xx(false, prologue, my_static_sec)?;
    let mut buf = vec![0u8; HANDSHAKE_MSG_CAP];
    let mut tmp = vec![0u8; HANDSHAKE_MSG_CAP];

    // <- e
    let msg1 = read_frame_raw(stream).await?;
    let _ = hs.read_message(&msg1, &mut tmp).map_err(snow_err)?;

    // h-snapshot for our signature (== h after reading msg1).
    let h_at_self_sign = hs.get_handshake_hash().to_vec();
    let to_sign = bind_signing_bytes(
        my_agent_id,
        my_x25519_pub,
        my_created_at_ms,
        &h_at_self_sign,
    );
    let sig = sign_blob(to_sign).await?;
    let my_proof = LanBindingProof {
        agent_id: *my_agent_id,
        x25519_pub: *my_x25519_pub,
        created_at_ms: my_created_at_ms,
        sig,
    };
    let payload = postcard::to_allocvec(&my_proof)
        .map_err(|e| ChatError::Invalid(format!("lan binding encode: {e}")))?;

    // -> e, ee, s, es + responder binding payload
    let len = hs.write_message(&payload, &mut buf).map_err(snow_err)?;
    write_frame_raw(stream, &buf[..len]).await?;

    // h-snapshot for verifying the initiator's signature (== h after
    // writing msg2; matches initiator's pre-write snapshot of msg3).
    let h_at_initiator_sign = hs.get_handshake_hash().to_vec();

    // <- s, se + initiator binding payload
    let msg3 = read_frame_raw(stream).await?;
    let payload_len = hs.read_message(&msg3, &mut tmp).map_err(snow_err)?;
    let peer_proof: LanBindingProof = postcard::from_bytes(&tmp[..payload_len])
        .map_err(|e| ChatError::Invalid(format!("lan binding decode: {e}")))?;
    verify_peer_binding(&hs, &peer_proof, &h_at_initiator_sign, peer_pubkey_lookup)?;

    let ts = hs.into_transport_mode().map_err(snow_err)?;
    Ok((
        ts,
        VerifiedPeer {
            agent_id: peer_proof.agent_id,
            x25519_pub: peer_proof.x25519_pub,
            created_at_ms: peer_proof.created_at_ms,
        },
    ))
}

fn bind_signing_bytes(
    agent_id: &[u8; 32],
    x25519_pub: &[u8; 32],
    created_at_ms: u64,
    handshake_hash: &[u8],
) -> Vec<u8> {
    let mut out = lan_binding_bytes(agent_id, x25519_pub, created_at_ms);
    out.extend_from_slice(handshake_hash);
    out
}

fn verify_peer_binding(
    hs: &HandshakeState,
    proof: &LanBindingProof,
    expected_h_at_sign: &[u8],
    peer_pubkey_lookup: &(dyn Fn(&[u8; 32]) -> Option<Vec<u8>> + Sync),
) -> Result<(), ChatError> {
    // The advertised peer agent_id must already be known via the
    // contact card (TOFU happens at share-URI import, never on the LAN).
    let peer_pk = peer_pubkey_lookup(&proof.agent_id).ok_or_else(|| {
        ChatError::Invalid(format!(
            "lan peer {} has no known ML-DSA pubkey",
            hex::encode(proof.agent_id)
        ))
    })?;

    // The X25519 in the proof must match the one snow recovered from
    // the handshake (e/s/es covers the wire authenticity; this catches
    // a peer that lies about its own static in the payload).
    let recovered = hs
        .get_remote_static()
        .ok_or_else(|| ChatError::Invalid("snow: no remote static".into()))?;
    if recovered != proof.x25519_pub {
        return Err(ChatError::Invalid(
            "lan binding x25519 mismatch with handshake static".into(),
        ));
    }

    let to_verify = bind_signing_bytes(
        &proof.agent_id,
        &proof.x25519_pub,
        proof.created_at_ms,
        expected_h_at_sign,
    );
    ml_dsa_verify(&peer_pk, &to_verify, &proof.sig)
}

/// Read and AEAD-decrypt one framed plaintext from `ts`.
///
/// # Errors
/// I/O, framing-cap, or AEAD failures.
pub async fn read_app_frame<R>(r: &mut R, ts: &mut TransportState) -> Result<Vec<u8>, ChatError>
where
    R: AsyncRead + Unpin,
{
    let ct = read_frame_raw(r).await?;
    let mut pt = vec![0u8; ct.len()];
    let len = ts.read_message(&ct, &mut pt).map_err(snow_err)?;
    pt.truncate(len);
    Ok(pt)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names,
    clippy::type_complexity
)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn fresh_static() -> [u8; 32] {
        use rand::RngCore;
        let mut s = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut s);
        s
    }

    #[tokio::test]
    async fn xx_handshake_completes_and_cipherstates_match() {
        let (mut a, mut b) = duplex(8192);
        let prologue = b"test-prologue".to_vec();
        let sec_i = fresh_static();
        let sec_r = fresh_static();

        let p_i = prologue.clone();
        let p_r = prologue.clone();
        let init = tokio::spawn(async move { run_initiator_plain(&mut a, &p_i, &sec_i).await });
        let resp = tokio::spawn(async move { run_responder_plain(&mut b, &p_r, &sec_r).await });

        let (mut ts_i, mut ts_r) = (init.await.unwrap().unwrap(), resp.await.unwrap().unwrap());

        // Reattach to fresh duplex halves for app traffic.
        let (mut a2, mut b2) = duplex(8192);
        let send_i: Vec<u8> = b"hello from initiator".to_vec();
        let send_r: Vec<u8> = b"hi back from responder".to_vec();
        let send_i_for_init = send_i.clone();
        let send_r_for_resp = send_r.clone();

        let t1 = tokio::spawn(async move {
            write_app_frame(&mut a2, &mut ts_i, &send_i_for_init)
                .await
                .unwrap();
            read_app_frame(&mut a2, &mut ts_i).await.unwrap()
        });
        let t2 = tokio::spawn(async move {
            let got = read_app_frame(&mut b2, &mut ts_r).await.unwrap();
            write_app_frame(&mut b2, &mut ts_r, &send_r_for_resp)
                .await
                .unwrap();
            got
        });

        let got_at_r = t2.await.unwrap();
        let got_at_i = t1.await.unwrap();
        assert_eq!(got_at_r, send_i);
        assert_eq!(got_at_i, send_r);
    }

    #[tokio::test]
    async fn prologue_mismatch_aborts_handshake() {
        let (mut a, mut b) = duplex(8192);
        let sec_i = fresh_static();
        let sec_r = fresh_static();

        let init =
            tokio::spawn(async move { run_initiator_plain(&mut a, b"prologue-A", &sec_i).await });
        let resp =
            tokio::spawn(async move { run_responder_plain(&mut b, b"prologue-B", &sec_r).await });

        let (ri, rr) = (init.await.unwrap(), resp.await.unwrap());
        assert!(
            ri.is_err() || rr.is_err(),
            "diverging prologue must fail at least one side"
        );
    }

    use fetchit_relay_client::{MlDsaSigner, Signer};
    use x25519_dalek::{PublicKey, StaticSecret};

    fn fresh_x25519() -> ([u8; 32], [u8; 32]) {
        let sec = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let pubk = PublicKey::from(&sec);
        (sec.to_bytes(), pubk.to_bytes())
    }

    /// Build a `peer_pubkey_lookup` callback bound to a single
    /// (`agent_id` → ML-DSA pubkey) mapping.
    fn single_lookup(aid: [u8; 32], pk: Vec<u8>) -> impl Fn(&[u8; 32]) -> Option<Vec<u8>> {
        move |q: &[u8; 32]| if *q == aid { Some(pk.clone()) } else { None }
    }

    fn make_signer_async(
        signer: std::sync::Arc<MlDsaSigner>,
    ) -> impl FnOnce(
        Vec<u8>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<u8>, ChatError>> + Send>,
    > {
        move |bytes| {
            Box::pin(async move {
                signer
                    .sign(&bytes)
                    .await
                    .map_err(|e| ChatError::Invalid(format!("test signer: {e}")))
            })
        }
    }

    #[tokio::test]
    async fn xx_with_binding_succeeds_when_signatures_verify() {
        let signer_i = std::sync::Arc::new(MlDsaSigner::generate().unwrap());
        let signer_r = std::sync::Arc::new(MlDsaSigner::generate().unwrap());
        let aid_i = [0x11u8; 32];
        let aid_r = [0x22u8; 32];
        let pk_i = signer_i.public_key();
        let pk_r = signer_r.public_key();

        let (sec_i, pub_i) = fresh_x25519();
        let (sec_r, pub_r) = fresh_x25519();
        let prologue = {
            let mut p = b"fetchit-lan-v1".to_vec();
            p.extend_from_slice(&aid_i);
            p.extend_from_slice(&aid_r);
            p
        };

        let (mut a, mut b) = duplex(16 * 1024);
        let p_i = prologue.clone();
        let p_r = prologue.clone();
        let lookup_for_i = single_lookup(aid_r, pk_r.clone());
        let lookup_for_r = single_lookup(aid_i, pk_i.clone());
        let s_i = signer_i.clone();
        let s_r = signer_r.clone();

        let init = tokio::spawn(async move {
            run_initiator_bound(
                &mut a,
                &p_i,
                &sec_i,
                &aid_i,
                &pub_i,
                100,
                make_signer_async(s_i),
                &lookup_for_i,
            )
            .await
        });
        let resp = tokio::spawn(async move {
            run_responder_bound(
                &mut b,
                &p_r,
                &sec_r,
                &aid_r,
                &pub_r,
                200,
                make_signer_async(s_r),
                &lookup_for_r,
            )
            .await
        });

        let (i_res, r_res) = (init.await.unwrap(), resp.await.unwrap());
        let (_ts_i, v_i) = i_res.unwrap();
        let (_ts_r, v_r) = r_res.unwrap();
        assert_eq!(v_i.agent_id, aid_r);
        assert_eq!(v_r.agent_id, aid_i);
        assert_eq!(v_i.x25519_pub, pub_r);
        assert_eq!(v_r.x25519_pub, pub_i);
        assert_eq!(v_i.created_at_ms, 200);
        assert_eq!(v_r.created_at_ms, 100);
    }

    #[tokio::test]
    async fn xx_aborts_when_responder_signature_is_forged() {
        let signer_i = std::sync::Arc::new(MlDsaSigner::generate().unwrap());
        // The "real" responder key — known on the initiator side
        let real_pk_r = MlDsaSigner::generate().unwrap().public_key();
        // The forger uses a DIFFERENT signer, but advertises real aid_r
        let forger = std::sync::Arc::new(MlDsaSigner::generate().unwrap());
        let aid_i = [0xaa; 32];
        let aid_r = [0xbb; 32];

        let (sec_i, pub_i) = fresh_x25519();
        let (sec_r, pub_r) = fresh_x25519();
        let prologue = {
            let mut p = b"fetchit-lan-v1".to_vec();
            p.extend_from_slice(&aid_i);
            p.extend_from_slice(&aid_r);
            p
        };

        let (mut a, mut b) = duplex(16 * 1024);
        let p_i = prologue.clone();
        let p_r = prologue.clone();
        let lookup_for_i = single_lookup(aid_r, real_pk_r);
        let lookup_for_r = single_lookup(aid_i, signer_i.public_key());
        let s_i = signer_i.clone();
        let s_forger = forger.clone();

        let init = tokio::spawn(async move {
            run_initiator_bound(
                &mut a,
                &p_i,
                &sec_i,
                &aid_i,
                &pub_i,
                100,
                make_signer_async(s_i),
                &lookup_for_i,
            )
            .await
        });
        let resp = tokio::spawn(async move {
            run_responder_bound(
                &mut b,
                &p_r,
                &sec_r,
                &aid_r,
                &pub_r,
                200,
                make_signer_async(s_forger),
                &lookup_for_r,
            )
            .await
        });

        let (i_res, _r_res) = (init.await.unwrap(), resp.await.unwrap());
        assert!(
            i_res.is_err(),
            "initiator must reject a binding signed by a wrong ML-DSA key"
        );
    }

    #[tokio::test]
    async fn xx_aborts_when_peer_pubkey_lookup_returns_none() {
        let signer_i = std::sync::Arc::new(MlDsaSigner::generate().unwrap());
        let signer_r = std::sync::Arc::new(MlDsaSigner::generate().unwrap());
        let aid_i = [0xcc; 32];
        let aid_r = [0xdd; 32];

        let (sec_i, pub_i) = fresh_x25519();
        let (sec_r, pub_r) = fresh_x25519();
        let prologue = {
            let mut p = b"fetchit-lan-v1".to_vec();
            p.extend_from_slice(&aid_i);
            p.extend_from_slice(&aid_r);
            p
        };

        let (mut a, mut b) = duplex(16 * 1024);
        let p_i = prologue.clone();
        let p_r = prologue.clone();
        // Initiator does NOT know responder's pubkey — stranger on LAN.
        let lookup_for_i = |_q: &[u8; 32]| -> Option<Vec<u8>> { None };
        let lookup_for_r = single_lookup(aid_i, signer_i.public_key());
        let s_i = signer_i.clone();
        let s_r = signer_r.clone();

        let init = tokio::spawn(async move {
            run_initiator_bound(
                &mut a,
                &p_i,
                &sec_i,
                &aid_i,
                &pub_i,
                100,
                make_signer_async(s_i),
                &lookup_for_i,
            )
            .await
        });
        let resp = tokio::spawn(async move {
            run_responder_bound(
                &mut b,
                &p_r,
                &sec_r,
                &aid_r,
                &pub_r,
                200,
                make_signer_async(s_r),
                &lookup_for_r,
            )
            .await
        });

        let (i_res, _r_res) = (init.await.unwrap(), resp.await.unwrap());
        assert!(
            i_res.is_err(),
            "unknown peer agent_id (no ML-DSA pubkey on file) must abort"
        );
    }

    #[tokio::test]
    async fn xx_aborts_when_prologue_diverges() {
        // Both sides have valid signers and known pubkeys, but they
        // disagree on the prologue → the handshake hashes diverge and
        // at least one binding verify fails. Models a peer claiming a
        // different identity in mDNS than they actually sign for.
        let signer_i = std::sync::Arc::new(MlDsaSigner::generate().unwrap());
        let signer_r = std::sync::Arc::new(MlDsaSigner::generate().unwrap());
        let aid_i = [0xee; 32];
        let aid_r = [0xff; 32];

        let (sec_i, pub_i) = fresh_x25519();
        let (sec_r, pub_r) = fresh_x25519();
        let prologue_i = {
            let mut p = b"fetchit-lan-v1".to_vec();
            p.extend_from_slice(&aid_i);
            p.extend_from_slice(&aid_r);
            p
        };
        let prologue_r = {
            // Responder thinks the initiator advertised a different aid
            let mut p = b"fetchit-lan-v1".to_vec();
            p.extend_from_slice(&[0u8; 32]);
            p.extend_from_slice(&aid_r);
            p
        };

        let (mut a, mut b) = duplex(16 * 1024);
        let lookup_for_i = single_lookup(aid_r, signer_r.public_key());
        let lookup_for_r = single_lookup(aid_i, signer_i.public_key());
        let s_i = signer_i.clone();
        let s_r = signer_r.clone();

        let init = tokio::spawn(async move {
            run_initiator_bound(
                &mut a,
                &prologue_i,
                &sec_i,
                &aid_i,
                &pub_i,
                100,
                make_signer_async(s_i),
                &lookup_for_i,
            )
            .await
        });
        let resp = tokio::spawn(async move {
            run_responder_bound(
                &mut b,
                &prologue_r,
                &sec_r,
                &aid_r,
                &pub_r,
                200,
                make_signer_async(s_r),
                &lookup_for_r,
            )
            .await
        });

        let (i_res, r_res) = (init.await.unwrap(), resp.await.unwrap());
        assert!(
            i_res.is_err() || r_res.is_err(),
            "diverging prologue must fail at least one side's verification"
        );
    }

    #[tokio::test]
    async fn write_frame_rejects_oversize() {
        let (mut a, _b) = duplex(8192);
        let big = vec![0u8; MAX_FRAME + 1];
        let err = write_frame_raw(&mut a, &big).await.unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("exceeds cap"), "got: {msg}");
    }
}
