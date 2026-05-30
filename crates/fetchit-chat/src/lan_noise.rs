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

use crate::error::ChatError;
use snow::{Builder, HandshakeState, TransportState};
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
    let params: snow::params::NoiseParams =
        NOISE_PARAMS.parse().map_err(|e: snow::Error| {
            ChatError::Invalid(format!("snow params: {e}"))
        })?;
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

/// Read and AEAD-decrypt one framed plaintext from `ts`.
///
/// # Errors
/// I/O, framing-cap, or AEAD failures.
pub async fn read_app_frame<R>(
    r: &mut R,
    ts: &mut TransportState,
) -> Result<Vec<u8>, ChatError>
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
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
        let init = tokio::spawn(async move {
            run_initiator_plain(&mut a, &p_i, &sec_i).await
        });
        let resp = tokio::spawn(async move {
            run_responder_plain(&mut b, &p_r, &sec_r).await
        });

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

        let init = tokio::spawn(async move {
            run_initiator_plain(&mut a, b"prologue-A", &sec_i).await
        });
        let resp = tokio::spawn(async move {
            run_responder_plain(&mut b, b"prologue-B", &sec_r).await
        });

        let (ri, rr) = (init.await.unwrap(), resp.await.unwrap());
        assert!(
            ri.is_err() || rr.is_err(),
            "diverging prologue must fail at least one side"
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
