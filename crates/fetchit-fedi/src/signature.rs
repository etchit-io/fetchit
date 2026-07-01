//! HTTP Signature signer for outbound `ActivityPub` deliveries.
//!
//! RFC 9421 primary path. The draft-cavage fallback lives in
//! `signature_cavage.rs`; the 24h per-instance capability cache lives
//! in `signature_cache.rs`.
//!
//! Algorithm: RSA-2048 + PKCS#1 v1.5 + SHA-256 (`rsa-v1_5-sha256`),
//! Mastodon's de-facto standard. Deterministic signature, so the same
//! `(key, body, date, created)` tuple always emits the same bytes —
//! that's what makes golden-vector tests possible.
//!
//! Per plan decision `[III]`, **no per-POST ML-DSA cosignature** — the
//! Actor JSON-LD ML-DSA attestation binding the RSA pubkey to the
//! chat identity is the authoritative PQ binding. Strict-RSA on the
//! per-POST surface keeps verifier code on the receiver side minimal.
//!
//! ## Covered components
//!
//! The RFC 9421 covered-component list emitted by this module is:
//!
//! ```text
//! ("@method" "@target-uri" "host" "date" "content-digest")
//! ```
//!
//! `Content-Digest` carries `sha-256=:<base64>:` of the body. The
//! caller attaches every field of [`SignedHeaders`] to the outbound
//! POST verbatim.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Per-actor HTTP Signature key bundle.
///
/// `key_id` is the fully-qualified `keyId` URL fetched and verified by
/// the receiving server (typically `<actor_url>#main-key`).
/// `rsa_private_pem` is the PKCS#8 PEM-encoded RSA-2048 private key.
///
/// The private key is a long-lived HTTP-Signature signing secret, so
/// this type zeroizes `rsa_private_pem` on drop and redacts it from
/// `Debug` (never log a `HttpSignatureKey`'s key material). Each
/// `Clone` owns an independent buffer that is likewise wiped on its own
/// drop.
#[derive(Clone)]
pub struct HttpSignatureKey {
    /// `keyId` URL (e.g. `https://etchit.io/actors/josh#main-key`).
    pub key_id: String,
    /// PKCS#8 PEM-encoded RSA-2048 private key.
    pub rsa_private_pem: String,
}

impl std::fmt::Debug for HttpSignatureKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpSignatureKey")
            .field("key_id", &self.key_id)
            .field("rsa_private_pem", &"<redacted>")
            .finish()
    }
}

impl Drop for HttpSignatureKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.rsa_private_pem.zeroize();
    }
}

/// Headers the caller adds to an outbound `application/activity+json`
/// POST so a Mastodon-class receiver can verify the request.
///
/// All four fields go on the wire verbatim; the receiver uses
/// `Signature-Input` to know which components were covered and
/// reconstructs the canonical signing base from them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedHeaders {
    /// `Date` header (IMF-fixdate / RFC 7231 §7.1.1.1).
    pub date: String,
    /// `Content-Digest` header — `sha-256=:<base64>:`.
    pub content_digest: String,
    /// `Signature-Input` header — `sig1=(...)...` with covered
    /// components, `created`, `keyid`, `alg`.
    pub signature_input: String,
    /// `Signature` header — `sig1=:<base64>:` over the canonical
    /// signing base.
    pub signature: String,
}

/// Errors from HTTP Signature construction.
#[derive(Debug, Error)]
pub enum HttpSignatureError {
    /// The PEM-encoded private key failed to decode.
    #[error("invalid RSA private key PEM: {0}")]
    InvalidPrivateKey(String),
    /// The signing URL has no host component (e.g. `file://`).
    #[error("url has no host component: {0}")]
    MissingHost(String),
    /// The underlying RSA signing operation failed.
    #[error("RSA signing failed: {0}")]
    SigningFailed(String),
}

impl HttpSignatureKey {
    /// Build the RFC 9421 [`SignedHeaders`] for a POST to `url` with
    /// the given `body`.
    ///
    /// `date_header` is the `Date` header value the caller will set on
    /// the outbound request (RFC 7231 IMF-fixdate, e.g.
    /// `"Sun, 06 Nov 1994 08:49:37 GMT"`). `created_unix` is the Unix
    /// timestamp emitted into `Signature-Input;created=` and bound
    /// into the canonical signing base; production callers should
    /// derive both from the same `SystemTime`.
    ///
    /// # Errors
    /// - [`HttpSignatureError::InvalidPrivateKey`] when the PEM fails
    ///   to decode.
    /// - [`HttpSignatureError::MissingHost`] when `url` has no host
    ///   component.
    /// - [`HttpSignatureError::SigningFailed`] when the underlying
    ///   RSA-SHA256 operation fails (effectively unreachable for a
    ///   well-formed 2048-bit key).
    pub fn sign_post_rfc9421(
        &self,
        url: &url::Url,
        body: &[u8],
        date_header: &str,
        created_unix: i64,
    ) -> Result<SignedHeaders, HttpSignatureError> {
        let priv_key = RsaPrivateKey::from_pkcs8_pem(&self.rsa_private_pem)
            .map_err(|e| HttpSignatureError::InvalidPrivateKey(format!("{e}")))?;
        let signing_key = SigningKey::<Sha256>::new(priv_key);
        sign_post_rfc9421_with_key(
            &signing_key,
            &self.key_id,
            url,
            body,
            date_header,
            created_unix,
        )
    }
}

/// Build the RFC 9421 [`SignedHeaders`] for a POST to `url`, using a
/// pre-decoded [`SigningKey<Sha256>`] so the PKCS#8 parse only runs
/// once per actor (rather than once per delivery). Used by
/// [`crate::transport::FediverseTransport`] which caches one
/// signing-key Arc per actor `key_id`.
///
/// Otherwise byte-identical to [`HttpSignatureKey::sign_post_rfc9421`].
///
/// # Errors
/// - [`HttpSignatureError::MissingHost`] when `url` has no host
///   component.
/// - [`HttpSignatureError::SigningFailed`] when the underlying
///   RSA-SHA256 operation fails.
pub fn sign_post_rfc9421_with_key(
    signing_key: &SigningKey<Sha256>,
    key_id: &str,
    url: &url::Url,
    body: &[u8],
    date_header: &str,
    created_unix: i64,
) -> Result<SignedHeaders, HttpSignatureError> {
    let content_digest = compute_content_digest(body);
    // Mastodon's `host_from_url` includes the port when non-default
    // (anything that isn't `443` over https or `80` over http).
    // `url::Url::port()` already normalizes default ports to `None`,
    // so we just append whatever `port()` returns. Without this, a
    // signer hitting `https://inbox.example:8443/inbox` would put
    // `host: inbox.example` in the canonical base while the Mastodon
    // verifier reconstructs `host: inbox.example:8443`, and every
    // POST to that server would silently fail verification.
    let host_str = url
        .host_str()
        .ok_or_else(|| HttpSignatureError::MissingHost(url.to_string()))?;
    let host = match url.port() {
        Some(port) => format!("{host_str}:{port}"),
        None => host_str.to_string(),
    };
    let sig_params = build_signature_input_params(created_unix, key_id);
    let signing_base = build_signature_base(
        url.as_str(),
        &host,
        date_header,
        &content_digest,
        &sig_params,
    );

    let signature = signing_key
        .try_sign(signing_base.as_bytes())
        .map_err(|e| HttpSignatureError::SigningFailed(format!("{e}")))?;
    let sig_b64 = B64.encode(signature.to_bytes());

    Ok(SignedHeaders {
        date: date_header.to_string(),
        content_digest,
        signature_input: format!("sig1={sig_params}"),
        signature: format!("sig1=:{sig_b64}:"),
    })
}

/// SHA-256 of `body` as a `Content-Digest` header value
/// (`sha-256=:<base64>:`, RFC 9530 structured-fields binary).
#[must_use]
pub fn compute_content_digest(body: &[u8]) -> String {
    let hash = Sha256::digest(body);
    format!("sha-256=:{}:", B64.encode(hash))
}

/// Build the RFC 9421 `Signature-Input` parameter portion (the part
/// after `sig1=`). The same string is appended to the canonical
/// signing base on the `@signature-params` line.
///
/// Note: RFC 9421 §2.3 SHOULD-NOT emit `alg`, but Mastodon emits and
/// accepts it (it's carried over from their cavage signatures and is
/// tolerated in 9421). We deliberately exceed the SHOULD-NOT for
/// Mastodon interop; dropping it would hurt verifier compatibility on
/// the install base.
fn build_signature_input_params(created_unix: i64, key_id: &str) -> String {
    format!(
        "(\"@method\" \"@target-uri\" \"host\" \"date\" \"content-digest\");\
         created={created_unix};\
         keyid=\"{key_id}\";\
         alg=\"rsa-v1_5-sha256\""
    )
}

/// Build the RFC 9421 canonical signing base.
///
/// Format:
/// ```text
/// "@method": POST
/// "@target-uri": <full target URI>
/// "host": <host>
/// "date": <date header value>
/// "content-digest": <Content-Digest value>
/// "@signature-params": <Signature-Input parameter portion>
/// ```
///
/// Lines joined by literal `\n`; **no trailing newline** after the
/// `@signature-params` line per RFC 9421 §2.5.
fn build_signature_base(
    target_uri: &str,
    host: &str,
    date: &str,
    content_digest: &str,
    sig_params: &str,
) -> String {
    format!(
        "\"@method\": POST\n\
         \"@target-uri\": {target_uri}\n\
         \"host\": {host}\n\
         \"date\": {date}\n\
         \"content-digest\": {content_digest}\n\
         \"@signature-params\": {sig_params}"
    )
}

/// Errors from inbound HTTP Signature verification.
///
/// Stage 3.1a — the receiver side of the wire-format symmetry. Every
/// variant is structured to map cleanly onto the relay-server inbox
/// gate's drop-reason label (so Prometheus
/// `fedi_inbox_dropped_sig_fail_total{reason}` stays a small finite
/// label set).
#[derive(Debug, Error)]
pub enum SignatureVerifyError {
    /// A required HTTP header was missing or could not be parsed.
    #[error("malformed signature header: {0}")]
    HeaderMalformed(String),
    /// `Content-Digest` did not match the SHA-256 of the body.
    #[error("Content-Digest header does not match body SHA-256")]
    DigestMismatch,
    /// The base64-encoded signature in the `Signature` header could
    /// not be decoded.
    #[error("signature payload base64 decode failed: {0}")]
    SignatureDecodeFailed(String),
    /// The RSA-SHA256 signature did not verify against the
    /// canonical signing base reconstructed from the request.
    #[error("RSA signature verification failed")]
    VerifyFailed,
}

impl SignatureVerifyError {
    /// Short label for Prometheus drop-reason counters. Keep the
    /// set small — every new variant is a new high-cardinality
    /// label slot.
    #[must_use]
    pub fn reason_label(&self) -> &'static str {
        match self {
            Self::HeaderMalformed(_) => "header_malformed",
            Self::DigestMismatch => "digest_mismatch",
            Self::SignatureDecodeFailed(_) => "signature_decode",
            Self::VerifyFailed => "verify_failed",
        }
    }
}

/// Verify the RFC 9421 HTTP Signature attached to an inbound
/// `application/activity+json` POST against `public_key`.
///
/// Reconstructs the canonical signing base byte-for-byte from the
/// caller-supplied request components (`build_signature_base`)
/// and verifies the base64-decoded signature with
/// `VerifyingKey<Sha256>`. Caller must derive `target_uri`/`host`
/// the same way the signer did — see Mastodon's `host_from_url`
/// rule preserved by [`HttpSignatureKey::sign_post_rfc9421`].
///
/// The covered-component list embedded in `signature_input` MUST
/// include `("@method" "@target-uri" "host" "date" "content-digest")`;
/// the receiver does not currently allow leaner subsets. Stricter
/// (more components) is fine — extras don't break verification
/// because the signing base is reconstructed verbatim from the
/// parameter portion.
///
/// `Content-Digest` is checked against `body`'s SHA-256 before the
/// RSA verify so a missing/incorrect digest fails fast with a
/// dedicated error variant for counter slicing.
///
/// # Errors
/// - [`SignatureVerifyError::HeaderMalformed`] for any structurally
///   invalid header value (missing `sig1=`, missing `signature`
///   parameter, etc.).
/// - [`SignatureVerifyError::DigestMismatch`] when `content_digest`
///   does not match SHA-256(body).
/// - [`SignatureVerifyError::SignatureDecodeFailed`] when the
///   `sig1=:<b64>:` payload is not valid base64.
/// - [`SignatureVerifyError::VerifyFailed`] on RSA verification
///   failure.
#[allow(clippy::too_many_arguments)]
pub fn verify_signature_rfc9421(
    public_key: &RsaPublicKey,
    target_uri: &str,
    host: &str,
    date: &str,
    content_digest: &str,
    signature_input: &str,
    signature: &str,
    body: &[u8],
) -> Result<(), SignatureVerifyError> {
    let expected_digest = compute_content_digest(body);
    if expected_digest != content_digest {
        return Err(SignatureVerifyError::DigestMismatch);
    }

    let sig_params = signature_input.strip_prefix("sig1=").ok_or_else(|| {
        SignatureVerifyError::HeaderMalformed("Signature-Input must start with 'sig1='".into())
    })?;

    let signing_base = build_signature_base(target_uri, host, date, content_digest, sig_params);

    let sig_b64 = signature
        .strip_prefix("sig1=:")
        .and_then(|s| s.strip_suffix(':'))
        .ok_or_else(|| {
            SignatureVerifyError::HeaderMalformed(
                "Signature must be of the form 'sig1=:<base64>:'".into(),
            )
        })?;

    let sig_bytes = B64
        .decode(sig_b64)
        .map_err(|e| SignatureVerifyError::SignatureDecodeFailed(format!("{e}")))?;
    let parsed_sig = Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| SignatureVerifyError::SignatureDecodeFailed(format!("{e}")))?;

    let verifying_key = VerifyingKey::<Sha256>::new(public_key.clone());
    verifying_key
        .verify(signing_base.as_bytes(), &parsed_sig)
        .map_err(|_| SignatureVerifyError::VerifyFailed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use rsa::rand_core::OsRng;
    use std::sync::OnceLock;

    /// Generate one RSA-2048 keypair per process and cache it. ~200ms
    /// keygen up-front, instant on every test thereafter.
    fn test_key_material() -> &'static (HttpSignatureKey, RsaPublicKey) {
        static KEY: OnceLock<(HttpSignatureKey, RsaPublicKey)> = OnceLock::new();
        KEY.get_or_init(|| {
            let priv_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
            let pub_key = priv_key.to_public_key();
            let priv_pem = priv_key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
            (
                HttpSignatureKey {
                    key_id: "https://etchit.io/actors/josh#main-key".into(),
                    rsa_private_pem: priv_pem,
                },
                pub_key,
            )
        })
    }

    #[test]
    fn compute_content_digest_pins_known_hash() {
        // SHA-256("hello world") = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
        // standard base64 = "uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="
        let digest = compute_content_digest(b"hello world");
        assert_eq!(
            digest,
            "sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:"
        );
    }

    #[test]
    fn compute_content_digest_empty_body() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let digest = compute_content_digest(b"");
        assert_eq!(
            digest,
            "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
        );
    }

    #[test]
    fn build_signature_input_params_pins_canonical_format() {
        let params =
            build_signature_input_params(783_000_000, "https://etchit.io/actors/josh#main-key");
        assert_eq!(
            params,
            "(\"@method\" \"@target-uri\" \"host\" \"date\" \"content-digest\");\
             created=783000000;\
             keyid=\"https://etchit.io/actors/josh#main-key\";\
             alg=\"rsa-v1_5-sha256\""
        );
    }

    #[test]
    fn build_signature_base_emits_canonical_layout() {
        let base = build_signature_base(
            "https://example.com/users/alice/inbox",
            "example.com",
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:",
            "(\"@method\" \"@target-uri\" \"host\" \"date\" \"content-digest\");\
             created=783000000;\
             keyid=\"https://etchit.io/actors/josh#main-key\";\
             alg=\"rsa-v1_5-sha256\"",
        );
        let expected = "\"@method\": POST\n\
                        \"@target-uri\": https://example.com/users/alice/inbox\n\
                        \"host\": example.com\n\
                        \"date\": Sun, 06 Nov 1994 08:49:37 GMT\n\
                        \"content-digest\": sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:\n\
                        \"@signature-params\": (\"@method\" \"@target-uri\" \"host\" \"date\" \"content-digest\");\
                        created=783000000;\
                        keyid=\"https://etchit.io/actors/josh#main-key\";\
                        alg=\"rsa-v1_5-sha256\"";
        assert_eq!(base, expected);
    }

    #[test]
    fn sign_post_rfc9421_self_verifies() {
        let (key, pub_key) = test_key_material();
        let url: url::Url = "https://example.com/users/alice/inbox".parse().unwrap();
        let body = br#"{"type":"Create","actor":"https://etchit.io/actors/josh"}"#;
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";
        let created = 783_000_000;

        let signed = key.sign_post_rfc9421(&url, body, date, created).unwrap();

        // Shape sanity-checks.
        assert!(signed.content_digest.starts_with("sha-256=:"));
        assert!(signed.content_digest.ends_with(':'));
        assert!(signed.signature_input.starts_with("sig1="));
        assert!(signed.signature.starts_with("sig1=:"));
        assert!(signed.signature.ends_with(':'));
        assert_eq!(signed.date, date);

        // Reconstruct the canonical signing base + signature exactly as
        // a Mastodon-class verifier would, then verify with the public
        // key.
        let sig_params = signed.signature_input.strip_prefix("sig1=").unwrap();
        let signing_base = build_signature_base(
            url.as_str(),
            "example.com",
            date,
            &signed.content_digest,
            sig_params,
        );
        let sig_b64 = signed
            .signature
            .strip_prefix("sig1=:")
            .unwrap()
            .strip_suffix(':')
            .unwrap();
        let sig_bytes = B64.decode(sig_b64).unwrap();
        let signature = Signature::try_from(sig_bytes.as_slice()).unwrap();

        let verifying_key = VerifyingKey::<Sha256>::new(pub_key.clone());
        verifying_key
            .verify(signing_base.as_bytes(), &signature)
            .expect("self-verify round-trip");
    }

    #[test]
    fn signature_changes_with_body() {
        let (key, _) = test_key_material();
        let url: url::Url = "https://example.com/users/alice/inbox".parse().unwrap();
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";
        let created = 783_000_000;

        let signed_a = key
            .sign_post_rfc9421(&url, b"body a", date, created)
            .unwrap();
        let signed_b = key
            .sign_post_rfc9421(&url, b"body b", date, created)
            .unwrap();
        assert_ne!(signed_a.content_digest, signed_b.content_digest);
        assert_ne!(signed_a.signature, signed_b.signature);
    }

    #[test]
    fn signature_changes_with_url() {
        let (key, _) = test_key_material();
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";
        let created = 783_000_000;
        let body = b"identical body";

        let signed_a = key
            .sign_post_rfc9421(
                &"https://example.com/users/alice/inbox".parse().unwrap(),
                body,
                date,
                created,
            )
            .unwrap();
        let signed_b = key
            .sign_post_rfc9421(
                &"https://example.com/users/bob/inbox".parse().unwrap(),
                body,
                date,
                created,
            )
            .unwrap();
        assert_eq!(signed_a.content_digest, signed_b.content_digest);
        assert_ne!(signed_a.signature, signed_b.signature);
    }

    #[test]
    fn tampered_body_fails_verification() {
        let (key, pub_key) = test_key_material();
        let url: url::Url = "https://example.com/users/alice/inbox".parse().unwrap();
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";
        let created = 783_000_000;

        let signed = key
            .sign_post_rfc9421(&url, b"original body", date, created)
            .unwrap();

        // Receiver substitutes a DIFFERENT body's digest into the
        // canonical base; the signature must fail.
        let tampered_digest = compute_content_digest(b"tampered body");
        let sig_params = signed.signature_input.strip_prefix("sig1=").unwrap();
        let signing_base = build_signature_base(
            url.as_str(),
            "example.com",
            date,
            &tampered_digest,
            sig_params,
        );
        let sig_b64 = signed
            .signature
            .strip_prefix("sig1=:")
            .unwrap()
            .strip_suffix(':')
            .unwrap();
        let sig_bytes = B64.decode(sig_b64).unwrap();
        let signature = Signature::try_from(sig_bytes.as_slice()).unwrap();

        let verifying_key = VerifyingKey::<Sha256>::new(pub_key.clone());
        assert!(verifying_key
            .verify(signing_base.as_bytes(), &signature)
            .is_err());
    }

    #[test]
    fn host_includes_non_default_port_for_mastodon_compat() {
        // Per Alice F-host-port: a signer hitting an inbox on a non-
        // default port MUST put `<host>:<port>` in the canonical base,
        // because Mastodon's `host_from_url` reconstructs the same.
        // Without this, `https://example.com:8443/inbox` deliveries
        // would silently fail verification — a nightmare to debug on a
        // remote receiver.
        let (key, pub_key) = test_key_material();
        let url: url::Url = "https://example.com:8443/inbox".parse().unwrap();
        let body = b"body";
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";
        let created = 783_000_000;

        let signed = key.sign_post_rfc9421(&url, body, date, created).unwrap();

        let sig_params = signed.signature_input.strip_prefix("sig1=").unwrap();
        let signing_base = build_signature_base(
            url.as_str(),
            "example.com:8443",
            date,
            &signed.content_digest,
            sig_params,
        );
        assert!(
            signing_base.contains("\"host\": example.com:8443\n"),
            "expected 'host: example.com:8443' in signing base; got:\n{signing_base}"
        );

        let sig_b64 = signed
            .signature
            .strip_prefix("sig1=:")
            .unwrap()
            .strip_suffix(':')
            .unwrap();
        let sig_bytes = B64.decode(sig_b64).unwrap();
        let signature = Signature::try_from(sig_bytes.as_slice()).unwrap();
        let verifying_key = VerifyingKey::<Sha256>::new(pub_key.clone());
        verifying_key
            .verify(signing_base.as_bytes(), &signature)
            .expect("self-verify with non-default port host");
    }

    #[test]
    fn host_omits_default_https_port() {
        // `url::Url::port()` returns `None` for default-scheme ports
        // (443 over https, 80 over http). The canonical base must NOT
        // carry `:443`, since that's also what Mastodon's verifier
        // reconstructs.
        let (key, pub_key) = test_key_material();
        let url: url::Url = "https://example.com/inbox".parse().unwrap();
        let body = b"body";
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";
        let created = 783_000_000;

        let signed = key.sign_post_rfc9421(&url, body, date, created).unwrap();

        let sig_params = signed.signature_input.strip_prefix("sig1=").unwrap();
        let signing_base = build_signature_base(
            url.as_str(),
            "example.com",
            date,
            &signed.content_digest,
            sig_params,
        );
        assert!(
            signing_base.contains("\"host\": example.com\n"),
            "expected bare host in signing base; got:\n{signing_base}"
        );
        assert!(
            !signing_base.contains(":443"),
            "default https port must not appear in canonical base"
        );

        let sig_b64 = signed
            .signature
            .strip_prefix("sig1=:")
            .unwrap()
            .strip_suffix(':')
            .unwrap();
        let sig_bytes = B64.decode(sig_b64).unwrap();
        let signature = Signature::try_from(sig_bytes.as_slice()).unwrap();
        let verifying_key = VerifyingKey::<Sha256>::new(pub_key.clone());
        verifying_key
            .verify(signing_base.as_bytes(), &signature)
            .expect("self-verify with default-port URL");
    }

    #[test]
    fn missing_host_in_url_surfaces_error() {
        let (key, _) = test_key_material();
        // file:// has no host component.
        let url: url::Url = "file:///tmp/whatever".parse().unwrap();
        let err = key
            .sign_post_rfc9421(&url, b"body", "Sun, 06 Nov 1994 08:49:37 GMT", 0)
            .unwrap_err();
        assert!(matches!(err, HttpSignatureError::MissingHost(_)));
    }

    #[test]
    fn invalid_private_key_surfaces_error() {
        let key = HttpSignatureKey {
            key_id: "https://etchit.io/actors/josh#main-key".into(),
            rsa_private_pem: "not a real PEM".into(),
        };
        let url: url::Url = "https://example.com/inbox".parse().unwrap();
        let err = key
            .sign_post_rfc9421(&url, b"body", "Sun, 06 Nov 1994 08:49:37 GMT", 0)
            .unwrap_err();
        assert!(matches!(err, HttpSignatureError::InvalidPrivateKey(_)));
    }

    // -------- Stage 3.1a verifier --------

    #[test]
    fn verify_signature_rfc9421_round_trip() {
        // Sign and verify with the same keypair — happy path.
        let (key, pub_key) = test_key_material();
        let url: url::Url = "https://example.com/users/alice/inbox".parse().unwrap();
        let body = br#"{"type":"Create","actor":"https://etchit.io/actors/josh"}"#;
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";
        let created = 783_000_000;

        let signed = key.sign_post_rfc9421(&url, body, date, created).unwrap();

        verify_signature_rfc9421(
            pub_key,
            url.as_str(),
            "example.com",
            date,
            &signed.content_digest,
            &signed.signature_input,
            &signed.signature,
            body,
        )
        .expect("round-trip verify");
    }

    #[test]
    fn verify_signature_rfc9421_tampered_body_fails_with_digest_mismatch() {
        let (key, pub_key) = test_key_material();
        let url: url::Url = "https://example.com/users/alice/inbox".parse().unwrap();
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";
        let created = 783_000_000;

        let signed = key
            .sign_post_rfc9421(&url, b"original", date, created)
            .unwrap();

        // Receiver gets a TAMPERED body but the same Content-Digest
        // header — caught by the digest-mismatch gate before RSA verify.
        let err = verify_signature_rfc9421(
            pub_key,
            url.as_str(),
            "example.com",
            date,
            &signed.content_digest,
            &signed.signature_input,
            &signed.signature,
            b"tampered",
        )
        .unwrap_err();
        assert!(matches!(err, SignatureVerifyError::DigestMismatch));
        assert_eq!(err.reason_label(), "digest_mismatch");
    }

    #[test]
    fn verify_signature_rfc9421_tampered_signature_fails() {
        let (key, pub_key) = test_key_material();
        let url: url::Url = "https://example.com/users/alice/inbox".parse().unwrap();
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";
        let created = 783_000_000;
        let body = b"identical body";

        let signed = key.sign_post_rfc9421(&url, body, date, created).unwrap();

        // Flip a middle character of the base64 payload — avoid the
        // trailing `==` padding so the decode still yields the same
        // 256-byte length, just different bytes. Result: well-formed
        // signature payload, but bytes don't verify against the body.
        let payload = signed
            .signature
            .strip_prefix("sig1=:")
            .unwrap()
            .strip_suffix(':')
            .unwrap();
        let mid = payload.len() / 2;
        let mid_char = payload.as_bytes()[mid];
        let replacement = if mid_char == b'A' { 'B' } else { 'A' };
        let mut tampered_payload = payload.to_string();
        tampered_payload.replace_range(mid..=mid, &replacement.to_string());
        let tampered_sig = format!("sig1=:{tampered_payload}:");

        let err = verify_signature_rfc9421(
            pub_key,
            url.as_str(),
            "example.com",
            date,
            &signed.content_digest,
            &signed.signature_input,
            &tampered_sig,
            body,
        )
        .unwrap_err();
        assert!(
            matches!(err, SignatureVerifyError::VerifyFailed),
            "expected VerifyFailed, got: {err:?}"
        );
        assert_eq!(err.reason_label(), "verify_failed");
    }

    #[test]
    fn verify_signature_rfc9421_malformed_signature_input_fails() {
        let (_, pub_key) = test_key_material();
        let url: url::Url = "https://example.com/inbox".parse().unwrap();
        let body = b"body";
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";

        let err = verify_signature_rfc9421(
            pub_key,
            url.as_str(),
            "example.com",
            date,
            &compute_content_digest(body),
            // No 'sig1=' prefix.
            "(\"@method\")",
            "sig1=:abcd:",
            body,
        )
        .unwrap_err();
        assert!(matches!(err, SignatureVerifyError::HeaderMalformed(_)));
        assert_eq!(err.reason_label(), "header_malformed");
    }

    #[test]
    fn verify_signature_rfc9421_malformed_signature_payload_fails() {
        let (_, pub_key) = test_key_material();
        let url: url::Url = "https://example.com/inbox".parse().unwrap();
        let body = b"body";
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";

        let err = verify_signature_rfc9421(
            pub_key,
            url.as_str(),
            "example.com",
            date,
            &compute_content_digest(body),
            "sig1=(\"@method\");created=0;keyid=\"x\";alg=\"rsa-v1_5-sha256\"",
            // Missing the 'sig1=:<b64>:' wrapper.
            "abcd",
            body,
        )
        .unwrap_err();
        assert!(matches!(err, SignatureVerifyError::HeaderMalformed(_)));
    }

    #[test]
    fn verify_signature_rfc9421_invalid_base64_fails() {
        let (_, pub_key) = test_key_material();
        let url: url::Url = "https://example.com/inbox".parse().unwrap();
        let body = b"body";
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";

        let err = verify_signature_rfc9421(
            pub_key,
            url.as_str(),
            "example.com",
            date,
            &compute_content_digest(body),
            "sig1=(\"@method\");created=0;keyid=\"x\";alg=\"rsa-v1_5-sha256\"",
            // Well-formed wrapper but the payload is not valid base64.
            "sig1=:!!!not-base64!!!:",
            body,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SignatureVerifyError::SignatureDecodeFailed(_)
        ));
        assert_eq!(err.reason_label(), "signature_decode");
    }

    #[test]
    fn verify_signature_rfc9421_wrong_pubkey_fails() {
        // Sign with one keypair, verify with a different pubkey ->
        // VerifyFailed.
        let (key, _) = test_key_material();
        let url: url::Url = "https://example.com/users/alice/inbox".parse().unwrap();
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";
        let created = 783_000_000;
        let body = b"body";

        let signed = key.sign_post_rfc9421(&url, body, date, created).unwrap();

        // Fresh second keypair just for this test — independent OnceLock
        // would be overkill.
        let other_priv = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let other_pub = other_priv.to_public_key();

        let err = verify_signature_rfc9421(
            &other_pub,
            url.as_str(),
            "example.com",
            date,
            &signed.content_digest,
            &signed.signature_input,
            &signed.signature,
            body,
        )
        .unwrap_err();
        assert!(matches!(err, SignatureVerifyError::VerifyFailed));
    }
}
