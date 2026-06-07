//! draft-cavage HTTP Signature signer for outbound `ActivityPub`
//! deliveries.
//!
//! Stage 2.1b sibling of [`crate::signature`] (RFC 9421). In practice
//! `draft-cavage` is **not** a fallback — it is the path that actually
//! works through proxied inboxes. RFC 9421's `@target-uri` covered
//! component is reconstructed by the receiver from `X-Forwarded-*`
//! headers and silently mismatches on any inbox sitting behind a
//! reverse proxy / CDN that rewrites scheme or host. cavage uses
//! `(request-target)` — just the relative path-and-query the receiver
//! sees on the wire — so it survives that topology.
//!
//! Wire shape:
//!
//! ```text
//! Date: Sun, 06 Nov 1994 08:49:37 GMT
//! Digest: SHA-256=<base64 of SHA-256(body)>
//! Signature: keyId="<key_id>",algorithm="rsa-sha256",
//!            headers="(request-target) host date digest",
//!            signature="<base64 of RSA-SHA256(signing-base)>"
//! ```
//!
//! Canonical signing base — lines joined by `\n`, no trailing newline:
//!
//! ```text
//! (request-target): post <path[?query]>
//! host: <host[:non-default-port]>
//! date: <Date header value>
//! digest: SHA-256=<base64>
//! ```
//!
//! `(request-target)` is `<method-lowercase> <path-and-query>` — no
//! scheme, no host. `host` follows the same `host_from_url` rule as
//! RFC 9421 (port suffix only when non-default), so we get byte parity
//! with Mastodon's verifier on the receive side.
//!
//! `Digest` is the original (pre-RFC 9530) `SHA-256=<base64>` form —
//! NOT the structured-fields `sha-256=:<b64>:` shape RFC 9421 uses.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};

use crate::signature::{HttpSignatureError, HttpSignatureKey};

/// Headers the caller attaches to an outbound `application/activity+json`
/// POST so a cavage-compatible receiver (every current Mastodon, all
/// Pleroma/Akkoma) can verify the request.
///
/// All three fields go on the wire verbatim. Unlike RFC 9421, there is
/// **no** `Signature-Input` — every parameter (`keyId`, `algorithm`,
/// `headers`, `signature`) is comma-separated inside the single
/// `Signature` header value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CavageSignedHeaders {
    /// `Date` header (IMF-fixdate / RFC 7231 §7.1.1.1).
    pub date: String,
    /// `Digest` header — `SHA-256=<base64>`.
    pub digest: String,
    /// `Signature` header — comma-separated `keyId="..."`,
    /// `algorithm="rsa-sha256"`, `headers="..."`, `signature="..."`.
    pub signature: String,
}

impl HttpSignatureKey {
    /// Build the draft-cavage [`CavageSignedHeaders`] for a POST to
    /// `url` with the given `body`.
    ///
    /// `date_header` is the `Date` header value the caller will set on
    /// the outbound request. The same string is bound into the
    /// canonical signing base; production callers should derive both
    /// from the same `SystemTime`.
    ///
    /// # Errors
    /// - [`HttpSignatureError::InvalidPrivateKey`] when the PEM fails
    ///   to decode.
    /// - [`HttpSignatureError::MissingHost`] when `url` has no host
    ///   component.
    /// - [`HttpSignatureError::SigningFailed`] when the underlying
    ///   RSA-SHA256 operation fails (effectively unreachable for a
    ///   well-formed 2048-bit key).
    pub fn sign_post_cavage(
        &self,
        url: &url::Url,
        body: &[u8],
        date_header: &str,
    ) -> Result<CavageSignedHeaders, HttpSignatureError> {
        let priv_key = RsaPrivateKey::from_pkcs8_pem(&self.rsa_private_pem)
            .map_err(|e| HttpSignatureError::InvalidPrivateKey(format!("{e}")))?;
        let signing_key = SigningKey::<Sha256>::new(priv_key);

        let digest = compute_digest_cavage(body);
        // Mirror RFC 9421 path host:port rule (`url::Url::port()`
        // normalises 443/80 to None) so a Mastodon receiver
        // reconstructs the same `host:` line via its
        // `host_from_url` helper.
        let host_str = url
            .host_str()
            .ok_or_else(|| HttpSignatureError::MissingHost(url.to_string()))?;
        let host = match url.port() {
            Some(port) => format!("{host_str}:{port}"),
            None => host_str.to_string(),
        };
        let request_target = build_request_target(url);
        let signing_base = build_cavage_base(&request_target, &host, date_header, &digest);

        let signature = signing_key
            .try_sign(signing_base.as_bytes())
            .map_err(|e| HttpSignatureError::SigningFailed(format!("{e}")))?;
        let sig_b64 = B64.encode(signature.to_bytes());

        let signature_header = format!(
            "keyId=\"{key_id}\",\
             algorithm=\"rsa-sha256\",\
             headers=\"(request-target) host date digest\",\
             signature=\"{sig_b64}\"",
            key_id = self.key_id,
        );

        Ok(CavageSignedHeaders {
            date: date_header.to_string(),
            digest,
            signature: signature_header,
        })
    }
}

/// SHA-256 of `body` as a draft-cavage `Digest` header value —
/// `SHA-256=<base64>`. Note: uppercase scheme, equals separator, no
/// structured-fields colons. Receivers using the cavage path expect
/// this exact shape.
#[must_use]
pub fn compute_digest_cavage(body: &[u8]) -> String {
    let hash = Sha256::digest(body);
    format!("SHA-256={}", B64.encode(hash))
}

/// Build the cavage `(request-target)` value: `<method-lowercase>
/// <path-and-query>`. POST is the only method we sign in this crate.
fn build_request_target(url: &url::Url) -> String {
    match url.query() {
        Some(q) => format!("post {}?{}", url.path(), q),
        None => format!("post {}", url.path()),
    }
}

/// Build the cavage canonical signing base.
///
/// Format:
/// ```text
/// (request-target): <request-target>
/// host: <host>
/// date: <date header value>
/// digest: <digest header value>
/// ```
///
/// Lines joined by `\n`; **no trailing newline** per draft-cavage-12
/// §2.3.
fn build_cavage_base(request_target: &str, host: &str, date: &str, digest: &str) -> String {
    format!(
        "(request-target): {request_target}\n\
         host: {host}\n\
         date: {date}\n\
         digest: {digest}"
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use rsa::rand_core::OsRng;
    use rsa::signature::Verifier;
    use rsa::RsaPublicKey;
    use std::sync::OnceLock;

    /// One RSA-2048 keypair per process. Cavage tests reuse the same
    /// cache as the RFC 9421 tests by keeping their own `OnceLock` — the
    /// two modules are independent compilation units.
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
    fn compute_digest_cavage_pins_known_hash() {
        // SHA-256("hello world") = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
        // standard base64 = "uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="
        // Cavage shape: uppercase scheme + `=` + bare base64, no colons.
        let digest = compute_digest_cavage(b"hello world");
        assert_eq!(
            digest,
            "SHA-256=uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="
        );
    }

    #[test]
    fn build_request_target_path_only() {
        let url: url::Url = "https://example.com/inbox/users/alice".parse().unwrap();
        assert_eq!(build_request_target(&url), "post /inbox/users/alice");
    }

    #[test]
    fn build_request_target_preserves_query() {
        // Mastodon receivers reconstruct (request-target) from the
        // actual HTTP request line, so query strings stay in.
        let url: url::Url = "https://example.com/inbox?foo=1&bar=baz".parse().unwrap();
        assert_eq!(build_request_target(&url), "post /inbox?foo=1&bar=baz");
    }

    #[test]
    fn build_cavage_base_emits_canonical_layout() {
        let base = build_cavage_base(
            "post /inbox/users/alice",
            "example.com",
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "SHA-256=uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=",
        );
        let expected = "(request-target): post /inbox/users/alice\n\
                        host: example.com\n\
                        date: Sun, 06 Nov 1994 08:49:37 GMT\n\
                        digest: SHA-256=uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=";
        assert_eq!(base, expected);
    }

    #[test]
    fn sign_post_cavage_self_verifies() {
        let (key, pub_key) = test_key_material();
        let url: url::Url = "https://example.com/users/alice/inbox".parse().unwrap();
        let body = br#"{"type":"Create","actor":"https://etchit.io/actors/josh"}"#;
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";

        let signed = key.sign_post_cavage(&url, body, date).unwrap();

        // Shape sanity.
        assert!(signed.digest.starts_with("SHA-256="));
        assert!(!signed.digest.contains(':'));
        assert!(signed.signature.contains("keyId=\""));
        assert!(signed.signature.contains("algorithm=\"rsa-sha256\""));
        assert!(signed
            .signature
            .contains("headers=\"(request-target) host date digest\""));
        assert!(signed.signature.contains("signature=\""));
        assert_eq!(signed.date, date);

        // Reconstruct the canonical signing base + signature exactly as
        // a Mastodon-class verifier would, then verify with the public
        // key.
        let signing_base = build_cavage_base(
            "post /users/alice/inbox",
            "example.com",
            date,
            &signed.digest,
        );
        let sig_b64 = signed
            .signature
            .rsplit("signature=\"")
            .next()
            .unwrap()
            .trim_end_matches('"');
        let sig_bytes = B64.decode(sig_b64).unwrap();
        let signature = Signature::try_from(sig_bytes.as_slice()).unwrap();

        let verifying_key = VerifyingKey::<Sha256>::new(pub_key.clone());
        verifying_key
            .verify(signing_base.as_bytes(), &signature)
            .expect("self-verify round-trip");
    }

    #[test]
    fn sign_post_cavage_non_default_port_included() {
        // Mirrors Alice F-host-port for the cavage path: a signer
        // hitting a non-default port MUST include `:<port>` in the
        // canonical base so the verifier reconstructs the same.
        let (key, pub_key) = test_key_material();
        let url: url::Url = "https://example.com:8443/inbox".parse().unwrap();
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";

        let signed = key.sign_post_cavage(&url, b"body", date).unwrap();

        let signing_base =
            build_cavage_base("post /inbox", "example.com:8443", date, &signed.digest);
        assert!(signing_base.contains("host: example.com:8443\n"));

        let sig_b64 = signed
            .signature
            .rsplit("signature=\"")
            .next()
            .unwrap()
            .trim_end_matches('"');
        let sig_bytes = B64.decode(sig_b64).unwrap();
        let signature = Signature::try_from(sig_bytes.as_slice()).unwrap();
        let verifying_key = VerifyingKey::<Sha256>::new(pub_key.clone());
        verifying_key
            .verify(signing_base.as_bytes(), &signature)
            .expect("self-verify with non-default port");
    }

    #[test]
    fn tampered_body_fails_cavage_verification() {
        let (key, pub_key) = test_key_material();
        let url: url::Url = "https://example.com/inbox".parse().unwrap();
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";

        let signed = key.sign_post_cavage(&url, b"original body", date).unwrap();

        // Receiver substitutes a DIFFERENT body's digest into the
        // canonical base; the signature must fail.
        let tampered_digest = compute_digest_cavage(b"tampered body");
        let signing_base = build_cavage_base("post /inbox", "example.com", date, &tampered_digest);
        let sig_b64 = signed
            .signature
            .rsplit("signature=\"")
            .next()
            .unwrap()
            .trim_end_matches('"');
        let sig_bytes = B64.decode(sig_b64).unwrap();
        let signature = Signature::try_from(sig_bytes.as_slice()).unwrap();
        let verifying_key = VerifyingKey::<Sha256>::new(pub_key.clone());
        assert!(verifying_key
            .verify(signing_base.as_bytes(), &signature)
            .is_err());
    }

    #[test]
    fn signature_changes_with_body_cavage() {
        let (key, _) = test_key_material();
        let url: url::Url = "https://example.com/inbox".parse().unwrap();
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";

        let a = key.sign_post_cavage(&url, b"body a", date).unwrap();
        let b = key.sign_post_cavage(&url, b"body b", date).unwrap();
        assert_ne!(a.digest, b.digest);
        assert_ne!(a.signature, b.signature);
    }

    #[test]
    fn signature_changes_with_path_cavage() {
        // Cavage covers `(request-target)`, which is path-only, so a
        // different path MUST produce a different signature even when
        // the body and host are the same.
        let (key, _) = test_key_material();
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";
        let body = b"identical body";

        let a = key
            .sign_post_cavage(
                &"https://example.com/users/alice/inbox".parse().unwrap(),
                body,
                date,
            )
            .unwrap();
        let b = key
            .sign_post_cavage(
                &"https://example.com/users/bob/inbox".parse().unwrap(),
                body,
                date,
            )
            .unwrap();
        assert_eq!(a.digest, b.digest);
        assert_ne!(a.signature, b.signature);
    }

    #[test]
    fn missing_host_in_url_surfaces_error_cavage() {
        let (key, _) = test_key_material();
        let url: url::Url = "file:///tmp/whatever".parse().unwrap();
        let err = key
            .sign_post_cavage(&url, b"body", "Sun, 06 Nov 1994 08:49:37 GMT")
            .unwrap_err();
        assert!(matches!(err, HttpSignatureError::MissingHost(_)));
    }

    #[test]
    fn invalid_private_key_surfaces_error_cavage() {
        let key = HttpSignatureKey {
            key_id: "https://etchit.io/actors/josh#main-key".into(),
            rsa_private_pem: "not a real PEM".into(),
        };
        let url: url::Url = "https://example.com/inbox".parse().unwrap();
        let err = key
            .sign_post_cavage(&url, b"body", "Sun, 06 Nov 1994 08:49:37 GMT")
            .unwrap_err();
        assert!(matches!(err, HttpSignatureError::InvalidPrivateKey(_)));
    }
}
