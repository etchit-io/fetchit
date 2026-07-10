//! Domain-separator constants used as signing-input prefixes.
//!
//! Every signed payload on the wire is built from
//! `DOMAIN_SEPARATOR || canonical(payload)` before hashing/signing.
//! The domain separator stops one signing context's bytes from being
//! confused for another (cross-protocol replay defence) and is the
//! load-bearing constant that pins the wire format.
//!
//! These constants are declared here so every consumer (relay
//! server, chat client, desktop wallet, future SDKs) imports the
//! same byte literal. The previous arrangement maintained
//! by-convention copies in `fetchit-chat`, `fetchit-relay-server`,
//! and `etchit-desktop` with a social-contract docstring saying
//! "must byte-match" — adversarial review caught that a future
//! edit in one place would break the wire silently. With the
//! constant living here, compile-time imports turn the social
//! contract into a build-time guarantee.
//!
//! Adding a new domain separator means appending a constant to
//! this module and re-exporting it from `lib.rs`. Never inline a
//! domain string at a call site.

/// Signing-input prefix for the profile manifest record.
///
/// The full signing input is
/// `SIGN_DOMAIN_PROFILE || jcs_canonical(record sans sig)`.
/// The 27-byte length is incidental — the value is the
/// load-bearing piece. Specified verbatim in
/// `docs/profile-manifest-v1.md` § 4.
pub const SIGN_DOMAIN_PROFILE: &[u8] = b"fetchit/profile-manifest/v1";

// ── x0x external-agent-sign framing (upstream x0x >= 0.29) ────────────────
//
// x0xd's `POST /agent/sign` no longer signs the raw payload: it signs
// `assemble_agent_sign_buffer(context, payload)` under a reserved namespace,
// so an externally-requested signature can never be replayed as an internal
// x0x commit signature. fetch>it's daemonless in-process signer and every
// verifier of an agent-key signature MUST reproduce these identical bytes, or
// the daemon and daemonless signing paths silently fail to verify each other
// across the fleet. Framing is verbatim from x0x `api/agent_signing.rs`.

/// Reserved leading namespace tag; disjoint from every internal x0x signing
/// input. Byte-identical to x0x `api::agent_signing::NAMESPACE_TAG`.
pub const AGENT_SIGN_NAMESPACE_TAG: u8 = 0xF0;

/// The external-agent-sign magic the DST is pinned to. Byte-identical to x0x
/// `api::agent_signing::MAGIC`.
pub const AGENT_SIGN_MAGIC: &[u8] = b"x0x.external-agent-sign.v1";

/// fetch>it's validated `context` on the external agent-sign path: lowercase
/// `[a-z0-9._-]`, non-empty, and not on x0x's internal denylist. Both the x0xd
/// HTTP signer and the daemonless signer pass this exact string so their
/// signatures cross-verify.
pub const AGENT_SIGN_CONTEXT: &str = "fetchit.agent-sign.v1";

/// The API-envelope scheme tag x0x's `POST /agent/sign` returns in its
/// `algorithm` field (byte-identical to x0x `api::agent_signing::SCHEME_ID`).
/// This is NOT a wire byte-prefix — it is the HTTP-response contract tag. The
/// x0xd HTTP signer requires the response to carry this exact string, so a
/// daemon still on the pre-`.v2` scheme (which signed raw / optional-domain
/// payloads) is rejected rather than silently trusted. `.v2` pins the
/// mandatory-context DST; it bumps in lockstep with the x0x pin.
pub const AGENT_SIGN_SCHEME_ID: &str = "x0x.agent-sign.v2.ml-dsa-65";

/// Reproduce x0x's `assemble_buffer`: the exact bytes x0xd signs for a
/// `/agent/sign` request carrying `context`. Framing:
/// `[TAG] || MAGIC || u32_be(len(context)) || context || payload`.
///
/// The daemonless in-process signer and every agent-key verifier call this so
/// the daemon and daemonless paths produce and check identical bytes.
#[must_use]
pub fn assemble_agent_sign_buffer(context: &str, payload: &[u8]) -> Vec<u8> {
    let ctx = context.as_bytes();
    let mut buf = Vec::with_capacity(1 + AGENT_SIGN_MAGIC.len() + 4 + ctx.len() + payload.len());
    buf.push(AGENT_SIGN_NAMESPACE_TAG);
    buf.extend_from_slice(AGENT_SIGN_MAGIC);
    // u32 big-endian context length → unambiguous context/payload boundary.
    let len = u32::try_from(ctx.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(ctx);
    buf.extend_from_slice(payload);
    buf
}

/// The exact bytes a fetch>it agent-key signature is computed over: the
/// external-agent-sign framing under fetch>it's fixed [`AGENT_SIGN_CONTEXT`].
///
/// Both the daemonless [`MlDsaSigner`](../fetchit_relay_client) producer and
/// every agent-key verifier call this one function, so a producer and a
/// verifier can never disagree on the context. (The x0xd HTTP signer produces
/// the same bytes by sending `context = AGENT_SIGN_CONTEXT` to the daemon,
/// which assembles the buffer itself.) Use this at verify sites — never
/// `assemble_agent_sign_buffer` with an ad-hoc context.
#[must_use]
pub fn agent_sign_input(message: &[u8]) -> Vec<u8> {
    assemble_agent_sign_buffer(AGENT_SIGN_CONTEXT, message)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn agent_sign_input_binds_the_fetchit_context() {
        // The verify-site helper must equal the general primitive under the
        // fixed context, or producers and verifiers drift apart.
        assert_eq!(
            agent_sign_input(b"m"),
            assemble_agent_sign_buffer(AGENT_SIGN_CONTEXT, b"m")
        );
    }

    #[test]
    fn assemble_agent_sign_buffer_matches_x0x_framing() {
        // Byte-pinned against x0x `assemble_buffer("ctx", b"payload")`.
        let a = assemble_agent_sign_buffer("ctx", b"payload");
        assert_eq!(a[0], 0xF0, "leading namespace tag");
        assert_eq!(
            &a[1..=AGENT_SIGN_MAGIC.len()],
            b"x0x.external-agent-sign.v1"
        );
        let off = 1 + AGENT_SIGN_MAGIC.len();
        assert_eq!(&a[off..off + 4], &3u32.to_be_bytes(), "u32 BE ctx length");
        assert_eq!(&a[off + 4..off + 7], b"ctx");
        assert_eq!(&a[off + 7..], b"payload");
    }

    #[test]
    fn length_prefix_prevents_context_payload_collision() {
        // (ab,cd) and (abc,d) share the raw bytes "abcd" but must be distinct.
        assert_ne!(
            assemble_agent_sign_buffer("ab", b"cd"),
            assemble_agent_sign_buffer("abc", b"d")
        );
    }

    #[test]
    fn fetchit_agent_sign_context_is_validate_context_safe() {
        // Mirrors x0x `validate_context`: non-empty, lowercase [a-z0-9._-].
        assert!(!AGENT_SIGN_CONTEXT.is_empty());
        assert!(AGENT_SIGN_CONTEXT.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        }));
    }
}
