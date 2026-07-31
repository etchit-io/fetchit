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
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

use crate::signature::{HttpSignatureError, HttpSignatureKey, SignatureVerifyError};

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
        sign_post_cavage_with_key(&signing_key, &self.key_id, url, body, date_header)
    }
}

/// Build the draft-cavage [`CavageSignedHeaders`] for a POST to `url`,
/// using a pre-decoded [`SigningKey<Sha256>`] so the PKCS#8 parse
/// runs once per actor (rather than once per delivery). Mirrors
/// [`crate::signature::sign_post_rfc9421_with_key`].
///
/// # Errors
/// - [`HttpSignatureError::MissingHost`] when `url` has no host
///   component.
/// - [`HttpSignatureError::SigningFailed`] when the underlying
///   RSA-SHA256 operation fails.
pub fn sign_post_cavage_with_key(
    signing_key: &SigningKey<Sha256>,
    key_id: &str,
    url: &url::Url,
    body: &[u8],
    date_header: &str,
) -> Result<CavageSignedHeaders, HttpSignatureError> {
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
         signature=\"{sig_b64}\""
    );

    Ok(CavageSignedHeaders {
        date: date_header.to_string(),
        digest,
        signature: signature_header,
    })
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

/// Parsed parameters of a draft-cavage `Signature` header value.
///
/// Only the fields the verifier actually uses are extracted; unknown
/// parameters (future cavage extensions) are silently ignored so a
/// new field on the wire does not break verification.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CavageSignatureParams {
    /// `keyId="<url>"` — the public key URL we look the actor up by.
    pub key_id: String,
    /// `algorithm="<algo>"` — e.g. `"rsa-sha256"`. NOT trusted for
    /// verification per draft-cavage-12 §3.2 (the verifier picks the
    /// algorithm from the key, not the header), but stashed for
    /// logging / counter labels.
    pub algorithm: String,
    /// `headers="(request-target) host date digest"` — the covered
    /// component list (space-separated, lowercase).
    pub headers: String,
    /// `signature="<base64>"` — the RSA-SHA256 signature payload.
    pub signature: String,
}

/// Parse a draft-cavage `Signature` header value into its
/// comma-separated `key="value"` parameters.
///
/// The split is quote-aware: separators inside `"..."` are part of
/// the value, not separators. This matters because the `signature`
/// parameter's base64 payload may contain `+`, `/`, `=` (padding)
/// and on rare occasions whitespace.
///
/// # Errors
/// - [`SignatureVerifyError::HeaderMalformed`] for any of:
///   - a parameter has no `=`,
///   - a value is not wrapped in `"..."`,
///   - the `signature` or `headers` parameter is empty (the verifier
///     needs both to do its job).
pub fn parse_cavage_signature_header(
    header_value: &str,
) -> Result<CavageSignatureParams, SignatureVerifyError> {
    let mut out = CavageSignatureParams::default();
    for part in quote_aware_split(header_value, ',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, raw_value) = part.split_once('=').ok_or_else(|| {
            SignatureVerifyError::HeaderMalformed(format!(
                "cavage Signature parameter missing '=': {part}"
            ))
        })?;
        let key = key.trim();
        let value = raw_value
            .trim()
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .ok_or_else(|| {
                SignatureVerifyError::HeaderMalformed(format!(
                    "cavage Signature value must be quoted: {key}={raw_value}"
                ))
            })?;
        match key {
            "keyId" => out.key_id = value.to_string(),
            "algorithm" => out.algorithm = value.to_string(),
            "headers" => out.headers = value.to_string(),
            "signature" => out.signature = value.to_string(),
            _ => {} // Future cavage extensions, ignore.
        }
    }
    if out.signature.is_empty() {
        return Err(SignatureVerifyError::HeaderMalformed(
            "cavage Signature is missing the 'signature' parameter".into(),
        ));
    }
    if out.headers.is_empty() {
        return Err(SignatureVerifyError::HeaderMalformed(
            "cavage Signature is missing the 'headers' parameter".into(),
        ));
    }
    Ok(out)
}

/// Split `s` on `sep`, but only when not inside a `"..."`-quoted
/// substring. Used by [`parse_cavage_signature_header`] so a
/// signature payload that happens to contain `,` doesn't tear the
/// parameter list apart.
fn quote_aware_split(s: &str, sep: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut in_quotes = false;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        if c == '"' {
            in_quotes = !in_quotes;
        } else if c == sep && !in_quotes {
            parts.push(&s[start..i]);
            start = i + c.len_utf8();
        }
    }
    parts.push(&s[start..]);
    parts
}

/// Verify the draft-cavage HTTP Signature attached to an inbound
/// POST against `public_key`.
///
/// Mirror of [`crate::signature::verify_signature_rfc9421`] for the
/// cavage wire format. Reconstructs the canonical signing base
/// byte-for-byte via `build_cavage_base` and verifies the
/// base64-decoded signature with `VerifyingKey<Sha256>`.
///
/// `request_target` is `<method-lowercase> <path[?query]>` — caller
/// derives it from the request line. `host` is the receiver's view
/// of the `Host` header (Mastodon's `host_from_url` rule
/// preserved). `digest` is the `Digest` header value
/// (`SHA-256=<b64>`); checked against the body's SHA-256 before
/// RSA verify.
///
/// # Errors
/// Identical semantics to
/// [`crate::signature::verify_signature_rfc9421`] — same
/// [`SignatureVerifyError`] variants.
pub fn verify_signature_cavage(
    public_key: &RsaPublicKey,
    request_target: &str,
    host: &str,
    date: &str,
    digest: &str,
    signature_header: &str,
    body: &[u8],
) -> Result<(), SignatureVerifyError> {
    let expected_digest = compute_digest_cavage(body);
    if expected_digest != digest {
        return Err(SignatureVerifyError::DigestMismatch);
    }

    let params = parse_cavage_signature_header(signature_header)?;

    let signing_base = build_cavage_base(request_target, host, date, digest);

    let sig_bytes = B64
        .decode(&params.signature)
        .map_err(|e| SignatureVerifyError::SignatureDecodeFailed(format!("{e}")))?;
    let parsed_sig = Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| SignatureVerifyError::SignatureDecodeFailed(format!("{e}")))?;

    let verifying_key = VerifyingKey::<Sha256>::new(public_key.clone());
    verifying_key
        .verify(signing_base.as_bytes(), &parsed_sig)
        .map_err(|_| SignatureVerifyError::VerifyFailed)
}

/// Minimum components a cavage `headers` list must cover before its
/// signature is worth anything: without these, a valid signature binds
/// nothing that matters (an attacker could sign only `date`).
const CAVAGE_REQUIRED_COMPONENTS: [&str; 4] = ["(request-target)", "host", "date", "digest"];

/// Verify a draft-cavage signature over the exact component list the
/// SIGNER declared (`headers="..."`), reconstructing each signing-base
/// line from the live request — what the spec requires of a verifier.
///
/// [`verify_signature_cavage`] instead checks a fixed 4-line base (our
/// own emitter's shape) and can never verify a Mastodon delivery,
/// which signs `(request-target) host date digest content-type` — the
/// 2026-07-14 zero-stored-replies root cause. The second stacked
/// killer: behind the etchit.io edge worker the received `Host` is the
/// origin vhost, not the public domain the sender signed — hence
/// `host_candidates`, tried in order (public domain first, received
/// `Host` second), at most one extra RSA verify.
///
/// The caller MUST have already validated the request's `digest`
/// header against the body and its `date` header against a skew
/// window — this function binds the presented headers to the key; it
/// does not re-check content freshness.
///
/// # Errors
/// - [`SignatureVerifyError::HeaderMalformed`] — unparseable
///   `Signature` header, or a declared list that fails to cover
///   `CAVAGE_REQUIRED_COMPONENTS`.
/// - [`SignatureVerifyError::MissingSignedHeader`] — the signer
///   declared a header the request does not carry.
/// - [`SignatureVerifyError::SignatureDecodeFailed`] — undecodable
///   signature payload.
/// - [`SignatureVerifyError::VerifyFailed`] — no host candidate
///   produces a verifying base.
pub fn verify_signature_cavage_declared(
    public_key: &RsaPublicKey,
    method: &str,
    path: &str,
    host_candidates: &[&str],
    req_header: &dyn Fn(&str) -> Option<String>,
    signature_header: &str,
) -> Result<(), SignatureVerifyError> {
    let params = parse_cavage_signature_header(signature_header)?;
    // Absent `headers` defaults to `date` alone per draft-cavage —
    // far below the required floor, so it fails the cover check.
    let declared: Vec<String> = if params.headers.trim().is_empty() {
        vec!["date".to_owned()]
    } else {
        params
            .headers
            .split_whitespace()
            .map(str::to_lowercase)
            .collect()
    };
    for required in CAVAGE_REQUIRED_COMPONENTS {
        if !declared.iter().any(|h| h == required) {
            return Err(SignatureVerifyError::HeaderMalformed(format!(
                "signed header list must cover {required}"
            )));
        }
    }

    let sig_bytes = B64
        .decode(&params.signature)
        .map_err(|e| SignatureVerifyError::SignatureDecodeFailed(format!("{e}")))?;
    let parsed_sig = Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| SignatureVerifyError::SignatureDecodeFailed(format!("{e}")))?;
    let verifying_key = VerifyingKey::<Sha256>::new(public_key.clone());

    let mut tried: Vec<&str> = Vec::with_capacity(host_candidates.len());
    for host in host_candidates {
        if tried.contains(host) {
            continue;
        }
        tried.push(host);
        let mut lines = Vec::with_capacity(declared.len());
        for name in &declared {
            let value = match name.as_str() {
                "(request-target)" => format!("{method} {path}"),
                "host" => (*host).to_owned(),
                other => req_header(other)
                    .ok_or_else(|| SignatureVerifyError::MissingSignedHeader(other.to_owned()))?,
            };
            lines.push(format!("{name}: {value}"));
        }
        if verifying_key
            .verify(lines.join("\n").as_bytes(), &parsed_sig)
            .is_ok()
        {
            return Ok(());
        }
    }
    Err(SignatureVerifyError::VerifyFailed)
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

    /// Sign an arbitrary base with the shared test key and wrap it in a
    /// cavage `Signature` header declaring `headers_list` — the shape a
    /// remote Mastodon emits, which our own [`sign_post_cavage`] never
    /// produces (it pins the 4-header list).
    fn sign_declared(headers_list: &str, base: &str) -> String {
        let (key, _) = test_key_material();
        let priv_key = RsaPrivateKey::from_pkcs8_pem(&key.rsa_private_pem).unwrap();
        let signing_key = SigningKey::<Sha256>::new(priv_key);
        let sig = B64.encode(signing_key.sign(base.as_bytes()).to_bytes());
        format!(
            "keyId=\"https://fosstodon.org/users/happyborg#main-key\",\
             algorithm=\"rsa-sha256\",headers=\"{headers_list}\",signature=\"{sig}\""
        )
    }

    fn mastodon_req_header(name: &str) -> Option<String> {
        match name {
            "date" => Some("Mon, 14 Jul 2026 10:00:00 GMT".to_owned()),
            "digest" => Some("SHA-256=uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=".to_owned()),
            "content-type" => Some("application/activity+json".to_owned()),
            _ => None,
        }
    }

    #[test]
    fn declared_verifies_mastodon_shape_with_content_type() {
        // The exact list every current Mastodon signs — five lines,
        // including content-type, which the fixed-base verifier can
        // never reconstruct.
        let list = "(request-target) host date digest content-type";
        let base = "(request-target): post /actors/josh/inbox\n\
                    host: etchit.io\n\
                    date: Mon, 14 Jul 2026 10:00:00 GMT\n\
                    digest: SHA-256=uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=\n\
                    content-type: application/activity+json";
        let sig = sign_declared(list, base);
        let (_, pub_key) = test_key_material();
        verify_signature_cavage_declared(
            pub_key,
            "post",
            "/actors/josh/inbox",
            // The edge-worker topology: received Host is the origin
            // vhost; the public domain the sender signed comes first.
            &["etchit.io", "bridge-origin.etchit.io"],
            &mastodon_req_header,
            &sig,
        )
        .expect("mastodon-shaped signature must verify");
    }

    #[test]
    fn declared_falls_through_host_candidates() {
        let list = "(request-target) host date digest";
        let base = "(request-target): post /actors/josh/inbox\n\
                    host: etchit.io\n\
                    date: Mon, 14 Jul 2026 10:00:00 GMT\n\
                    digest: SHA-256=uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=";
        let sig = sign_declared(list, base);
        let (_, pub_key) = test_key_material();
        // Signed host is only the SECOND candidate — must still verify.
        verify_signature_cavage_declared(
            pub_key,
            "post",
            "/actors/josh/inbox",
            &["bridge-origin.etchit.io", "etchit.io"],
            &mastodon_req_header,
            &sig,
        )
        .expect("second host candidate must be tried");
        // No candidate matches what was signed → VerifyFailed. This is
        // the pre-fix production topology (received Host only).
        let err = verify_signature_cavage_declared(
            pub_key,
            "post",
            "/actors/josh/inbox",
            &["bridge-origin.etchit.io"],
            &mastodon_req_header,
            &sig,
        )
        .unwrap_err();
        assert!(matches!(err, SignatureVerifyError::VerifyFailed));
    }

    #[test]
    fn declared_rejects_under_covered_header_list() {
        // A valid signature over a list that omits digest binds
        // nothing — must be rejected before any RSA math.
        let list = "(request-target) host date";
        let base = "(request-target): post /actors/josh/inbox\n\
                    host: etchit.io\n\
                    date: Mon, 14 Jul 2026 10:00:00 GMT";
        let sig = sign_declared(list, base);
        let (_, pub_key) = test_key_material();
        let err = verify_signature_cavage_declared(
            pub_key,
            "post",
            "/actors/josh/inbox",
            &["etchit.io"],
            &mastodon_req_header,
            &sig,
        )
        .unwrap_err();
        assert!(matches!(err, SignatureVerifyError::HeaderMalformed(_)));
    }

    #[test]
    fn declared_reports_missing_signed_header() {
        // Signer declared a header the request doesn't carry.
        let list = "(request-target) host date digest x-custom";
        let base = "(request-target): post /actors/josh/inbox\n\
                    host: etchit.io\n\
                    date: Mon, 14 Jul 2026 10:00:00 GMT\n\
                    digest: SHA-256=uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=\n\
                    x-custom: nope";
        let sig = sign_declared(list, base);
        let (_, pub_key) = test_key_material();
        let err = verify_signature_cavage_declared(
            pub_key,
            "post",
            "/actors/josh/inbox",
            &["etchit.io"],
            &mastodon_req_header,
            &sig,
        )
        .unwrap_err();
        assert!(matches!(err, SignatureVerifyError::MissingSignedHeader(h) if h == "x-custom"));
    }

    #[test]
    fn declared_preserves_signer_header_order() {
        // The base must follow the DECLARED order, not a canonical one.
        let list = "host (request-target) digest date";
        let base = "host: etchit.io\n\
                    (request-target): post /actors/josh/inbox\n\
                    digest: SHA-256=uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=\n\
                    date: Mon, 14 Jul 2026 10:00:00 GMT";
        let sig = sign_declared(list, base);
        let (_, pub_key) = test_key_material();
        verify_signature_cavage_declared(
            pub_key,
            "post",
            "/actors/josh/inbox",
            &["etchit.io"],
            &mastodon_req_header,
            &sig,
        )
        .expect("declared order must drive base construction");
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

    // -------- Stage 3.1a cavage parser + verifier --------

    #[test]
    fn parse_cavage_signature_header_extracts_all_params() {
        let header = r#"keyId="https://example.com/actors/alice#main-key",algorithm="rsa-sha256",headers="(request-target) host date digest",signature="ABCDEF=="#.to_string()
            + r#"""#;
        let parsed = parse_cavage_signature_header(&header).unwrap();
        assert_eq!(parsed.key_id, "https://example.com/actors/alice#main-key");
        assert_eq!(parsed.algorithm, "rsa-sha256");
        assert_eq!(parsed.headers, "(request-target) host date digest");
        assert_eq!(parsed.signature, "ABCDEF==");
    }

    #[test]
    fn parse_cavage_signature_header_ignores_unknown_params() {
        // Future cavage extensions should not break verification.
        let header = r#"keyId="x",algorithm="rsa-sha256",headers="host date digest",signature="ABC",created="1700000000""#;
        let parsed = parse_cavage_signature_header(header).unwrap();
        assert_eq!(parsed.key_id, "x");
        assert_eq!(parsed.signature, "ABC");
    }

    #[test]
    fn parse_cavage_signature_header_quote_aware_split() {
        // Comma INSIDE quoted value must not split the parameter list.
        // (Real signature payloads can contain `+/=` but not `,` — this
        // is a defence-in-depth canary anyway.)
        let header = r#"keyId="x",signature="ABC,DEF",headers="host""#;
        let parsed = parse_cavage_signature_header(header).unwrap();
        assert_eq!(parsed.signature, "ABC,DEF");
    }

    #[test]
    fn parse_cavage_signature_header_missing_signature_fails() {
        let header = r#"keyId="x",algorithm="rsa-sha256",headers="host""#;
        let err = parse_cavage_signature_header(header).unwrap_err();
        assert!(matches!(err, SignatureVerifyError::HeaderMalformed(_)));
        let msg = format!("{err}");
        assert!(msg.contains("signature"), "got: {msg}");
    }

    #[test]
    fn parse_cavage_signature_header_missing_headers_fails() {
        let header = r#"keyId="x",signature="ABC""#;
        let err = parse_cavage_signature_header(header).unwrap_err();
        assert!(matches!(err, SignatureVerifyError::HeaderMalformed(_)));
        let msg = format!("{err}");
        assert!(msg.contains("headers"), "got: {msg}");
    }

    #[test]
    fn parse_cavage_signature_header_unquoted_value_fails() {
        let header = r#"keyId=x,signature="ABC",headers="host""#;
        let err = parse_cavage_signature_header(header).unwrap_err();
        assert!(matches!(err, SignatureVerifyError::HeaderMalformed(_)));
    }

    #[test]
    fn parse_cavage_signature_header_no_equals_fails() {
        let header = r#"keyId="x",just-a-flag,signature="ABC",headers="host""#;
        let err = parse_cavage_signature_header(header).unwrap_err();
        assert!(matches!(err, SignatureVerifyError::HeaderMalformed(_)));
    }

    #[test]
    fn verify_signature_cavage_round_trip() {
        let (key, pub_key) = test_key_material();
        let url: url::Url = "https://example.com/users/alice/inbox".parse().unwrap();
        let body = br#"{"type":"Create","actor":"https://etchit.io/actors/josh"}"#;
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";

        let signed = key.sign_post_cavage(&url, body, date).unwrap();

        verify_signature_cavage(
            pub_key,
            "post /users/alice/inbox",
            "example.com",
            date,
            &signed.digest,
            &signed.signature,
            body,
        )
        .expect("cavage round-trip verify");
    }

    #[test]
    fn verify_signature_cavage_non_default_port_round_trip() {
        // Mirror the Stage 2.1a Alice F-host-port fix on the receive
        // side: a signer that included `:8443` must produce a base
        // that the verifier reconstructs the same way.
        let (key, pub_key) = test_key_material();
        let url: url::Url = "https://example.com:8443/inbox".parse().unwrap();
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";

        let signed = key.sign_post_cavage(&url, b"body", date).unwrap();
        verify_signature_cavage(
            pub_key,
            "post /inbox",
            "example.com:8443",
            date,
            &signed.digest,
            &signed.signature,
            b"body",
        )
        .expect("non-default port cavage verify");
    }

    #[test]
    fn verify_signature_cavage_tampered_body_fails_with_digest_mismatch() {
        let (key, pub_key) = test_key_material();
        let url: url::Url = "https://example.com/inbox".parse().unwrap();
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";

        let signed = key.sign_post_cavage(&url, b"original", date).unwrap();

        let err = verify_signature_cavage(
            pub_key,
            "post /inbox",
            "example.com",
            date,
            &signed.digest,
            &signed.signature,
            b"tampered",
        )
        .unwrap_err();
        assert!(matches!(err, SignatureVerifyError::DigestMismatch));
    }

    #[test]
    fn verify_signature_cavage_tampered_signature_fails() {
        let (key, pub_key) = test_key_material();
        let url: url::Url = "https://example.com/inbox".parse().unwrap();
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";
        let body = b"identical body";

        let signed = key.sign_post_cavage(&url, body, date).unwrap();

        // Mid-of-payload flip (skip trailing == padding).
        let params = parse_cavage_signature_header(&signed.signature).unwrap();
        let mid = params.signature.len() / 2;
        let mid_char = params.signature.as_bytes()[mid];
        let replacement = if mid_char == b'A' { 'B' } else { 'A' };
        let mut tampered_payload = params.signature.clone();
        tampered_payload.replace_range(mid..=mid, &replacement.to_string());
        let tampered_header = format!(
            "keyId=\"{}\",algorithm=\"rsa-sha256\",headers=\"{}\",signature=\"{}\"",
            params.key_id, params.headers, tampered_payload,
        );

        let err = verify_signature_cavage(
            pub_key,
            "post /inbox",
            "example.com",
            date,
            &signed.digest,
            &tampered_header,
            body,
        )
        .unwrap_err();
        assert!(matches!(err, SignatureVerifyError::VerifyFailed));
    }

    #[test]
    fn verify_signature_cavage_wrong_pubkey_fails() {
        let (key, _) = test_key_material();
        let url: url::Url = "https://example.com/inbox".parse().unwrap();
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";
        let body = b"body";

        let signed = key.sign_post_cavage(&url, body, date).unwrap();

        let other_priv = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let other_pub = other_priv.to_public_key();
        let err = verify_signature_cavage(
            &other_pub,
            "post /inbox",
            "example.com",
            date,
            &signed.digest,
            &signed.signature,
            body,
        )
        .unwrap_err();
        assert!(matches!(err, SignatureVerifyError::VerifyFailed));
    }
}
