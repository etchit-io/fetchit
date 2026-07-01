//! Inbox-side HTTP Signature verification wrapper.
//!
//! Stage 3.1b gate 2. Per Alice's suggestion in the 3.1a
//! cross-review: a thin axum-shaped extractor around
//! [`fetchit_fedi::signature::verify_signature_rfc9421`] /
//! [`fetchit_fedi::signature_cavage::verify_signature_cavage`] that
//! pulls headers + reconstructs the Mastodon-shaped `@target-uri`
//! in one call so the policy / crypto boundary stays clean.
//!
//! The verifier itself stays wire-format-policy-agnostic: the policy
//! checks (`algorithm="rsa-sha256"` only, `Date`/`created` skew) live
//! here, not in `fetchit-fedi`.

use std::time::SystemTime;

use axum::http::HeaderMap;
use fetchit_fedi::signature::{verify_signature_rfc9421, SignatureVerifyError};
use fetchit_fedi::signature_cavage::{parse_cavage_signature_header, verify_signature_cavage};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;

use super::DropReason;

/// Wire format an inbound request used. Determines which verifier
/// downstream gets called.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureScheme {
    /// RFC 9421 — `Signature-Input` + `Signature` headers,
    /// `Content-Digest: sha-256=:<b64>:`.
    Rfc9421,
    /// draft-cavage — single `Signature` header, `Digest:
    /// SHA-256=<b64>`.
    Cavage,
}

/// Components a Mastodon-class verifier needs to reconstruct.
///
/// Built by [`extract_inbox_signature_context`] from an axum
/// `HeaderMap` + the request URI; passed to [`verify_inbox_request`]
/// alongside the body bytes + the resolved public key.
#[derive(Clone, Debug)]
pub struct InboxSignatureContext {
    /// Which wire format the request used.
    pub scheme: SignatureScheme,
    /// `keyId` URL — parsed from `Signature-Input` (RFC 9421) or
    /// `Signature` (cavage).
    pub key_id: String,
    /// Date header value as the signer emitted it.
    pub date: String,
    /// `Content-Digest` value (RFC 9421) or `Digest` value (cavage).
    /// Format differs by scheme — passed verbatim to the verifier.
    pub digest: String,
    /// `Signature-Input` (RFC 9421) header value. Empty for cavage.
    pub signature_input: String,
    /// `Signature` header value verbatim.
    pub signature: String,
    /// Mastodon's `host_from_url` — the host as the signer would have
    /// encoded it (with port suffix if non-default for the scheme).
    pub host: String,
    /// Reconstructed `@target-uri` — used by RFC 9421 only.
    pub target_uri: String,
    /// Cavage `(request-target)` — used by cavage only.
    pub request_target: String,
}

/// Extract everything needed to verify an inbound POST signature.
///
/// `reconstruct_target_uri`/`reconstruct_request_target` use the
/// `Host` header + the path + any `X-Forwarded-*` overrides if
/// present. This is the brittleness Alice flagged in the Stage 2.1b
/// cross-review on the outbound side — same issue surfacing on the
/// inbound side.
///
/// # Errors
/// [`DropReason::MissingHeader`] / [`DropReason::MissingKeyId`] when
/// the request is structurally incomplete for either wire format.
pub fn extract_inbox_signature_context(
    headers: &HeaderMap,
    request_path: &str,
) -> Result<InboxSignatureContext, DropReason> {
    let signature =
        header_value(headers, "signature").ok_or(DropReason::MissingHeader("signature"))?;
    let date = header_value(headers, "date").ok_or(DropReason::MissingHeader("date"))?;
    let host = read_host(headers)?;

    // RFC 9421 carries an explicit `Signature-Input` header — its
    // presence is the discriminator between the two wire formats.
    let signature_input = header_value(headers, "signature-input");

    if let Some(sig_input) = signature_input {
        // RFC 9421 path.
        let content_digest = header_value(headers, "content-digest")
            .ok_or(DropReason::MissingHeader("content-digest"))?;
        let target_uri = reconstruct_target_uri(headers, request_path)?;
        let key_id = parse_rfc9421_keyid(&sig_input).ok_or(DropReason::MissingKeyId)?;
        Ok(InboxSignatureContext {
            scheme: SignatureScheme::Rfc9421,
            key_id,
            date,
            digest: content_digest,
            signature_input: sig_input,
            signature,
            host,
            target_uri,
            request_target: String::new(),
        })
    } else {
        // Cavage path.
        let digest = header_value(headers, "digest").ok_or(DropReason::MissingHeader("digest"))?;
        let parsed = parse_cavage_signature_header(&signature)
            .map_err(|_| DropReason::SigFail("header_malformed"))?;
        if parsed.key_id.is_empty() {
            return Err(DropReason::MissingKeyId);
        }
        let request_target = build_request_target(headers, request_path);
        Ok(InboxSignatureContext {
            scheme: SignatureScheme::Cavage,
            key_id: parsed.key_id,
            date,
            digest,
            signature_input: String::new(),
            signature,
            host,
            target_uri: String::new(),
            request_target,
        })
    }
}

/// Verify the inbound request against `pubkey_pem`.
///
/// Walks the appropriate fetchit-fedi verifier for the scheme
/// recorded on `ctx`. Returns the wire-format scheme used on
/// success so the caller can route metrics / future cap-cache
/// updates.
///
/// # Errors
/// [`DropReason::SigFail`] for any verification failure (digest
/// mismatch, signature decode failure, RSA verify failure, malformed
/// header). [`DropReason::UnsupportedAlgorithm`] when the cavage
/// `algorithm=` parameter is not `"rsa-sha256"`.
pub fn verify_inbox_request(
    pubkey_pem: &str,
    ctx: &InboxSignatureContext,
    body: &[u8],
) -> Result<SignatureScheme, DropReason> {
    let pubkey =
        parse_rsa_public_key_pem(pubkey_pem).ok_or(DropReason::SigFail("pubkey_decode"))?;

    match ctx.scheme {
        SignatureScheme::Rfc9421 => verify_signature_rfc9421(
            &pubkey,
            &ctx.target_uri,
            &ctx.host,
            &ctx.date,
            &ctx.digest,
            &ctx.signature_input,
            &ctx.signature,
            body,
        )
        .map(|()| SignatureScheme::Rfc9421)
        .map_err(|e| map_verify_err(&e)),
        SignatureScheme::Cavage => {
            // Alice's I2: cavage parser already extracted algorithm.
            // Re-parse here (cheap; ~600 bytes of header) so the
            // policy check is local to the verifier-call site
            // rather than the extractor.
            let parsed = parse_cavage_signature_header(&ctx.signature)
                .map_err(|_| DropReason::SigFail("header_malformed"))?;
            if !parsed.algorithm.is_empty() && parsed.algorithm != "rsa-sha256" {
                return Err(DropReason::UnsupportedAlgorithm);
            }
            verify_signature_cavage(
                &pubkey,
                &ctx.request_target,
                &ctx.host,
                &ctx.date,
                &ctx.digest,
                &ctx.signature,
                body,
            )
            .map(|()| SignatureScheme::Cavage)
            .map_err(|e| map_verify_err(&e))
        }
    }
}

/// Convert an `fetchit_fedi::SignatureVerifyError` into the inbox's
/// `DropReason::SigFail(label)` shape. Preserves the Prom counter
/// sub-label sizing decision from Stage 3.1a.
#[must_use]
pub fn map_verify_err(err: &SignatureVerifyError) -> DropReason {
    DropReason::SigFail(err.reason_label())
}

/// Reconstruct the RFC 9421 `@target-uri` from request headers +
/// path. Honours `X-Forwarded-Proto` + `X-Forwarded-Host` so a
/// proxied receiver matches what the signer claimed — the same path
/// Mastodon's verifier walks.
fn reconstruct_target_uri(headers: &HeaderMap, request_path: &str) -> Result<String, DropReason> {
    let host = read_host(headers)?;
    let scheme = header_value(headers, "x-forwarded-proto").unwrap_or_else(|| "https".to_string());
    let forwarded_host = header_value(headers, "x-forwarded-host");
    let host = forwarded_host.unwrap_or(host);
    Ok(format!("{scheme}://{host}{request_path}"))
}

/// Build the cavage `(request-target)` — `<method-lowercase>
/// <path-and-query>`. POST is the only method we accept here.
fn build_request_target(_headers: &HeaderMap, request_path: &str) -> String {
    format!("post {request_path}")
}

/// Parse the `Host` header (or fall back to `X-Forwarded-Host`) and
/// return it exactly as the signer would have encoded it. Mirrors
/// Mastodon's `host_from_url` — preserves any explicit port suffix.
fn read_host(headers: &HeaderMap) -> Result<String, DropReason> {
    if let Some(host) = header_value(headers, "x-forwarded-host") {
        return Ok(host);
    }
    header_value(headers, "host").ok_or(DropReason::MissingHeader("host"))
}

/// Header lookup helper, case-insensitive (`HeaderMap` already is) +
/// owned String for use in further string ops.
fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(name)?.to_str().ok().map(ToOwned::to_owned)
}

/// Extract the `keyid="..."` parameter from an RFC 9421
/// `Signature-Input` header value.
fn parse_rfc9421_keyid(signature_input: &str) -> Option<String> {
    let marker = "keyid=\"";
    let start = signature_input.find(marker)? + marker.len();
    let rest = &signature_input[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Decode a PEM-encoded RSA public key from either `SubjectPublicKeyInfo`
/// (`-----BEGIN PUBLIC KEY-----`) or the older PKCS#1
/// (`-----BEGIN RSA PUBLIC KEY-----`) envelope. Mastodon emits the
/// former; some Pleroma forks emit the latter.
fn parse_rsa_public_key_pem(pem: &str) -> Option<RsaPublicKey> {
    if let Ok(k) = RsaPublicKey::from_public_key_pem(pem) {
        return Some(k);
    }
    RsaPublicKey::from_pkcs1_pem(pem).ok()
}

/// Check that the `Date` header is within `max_skew` of `now`.
///
/// Production callers should derive `now` from `SystemTime::now()`.
/// Tests pass a fixed `SystemTime` for determinism. Date parsing is
/// IMF-fixdate per RFC 7231 §7.1.1.1.
///
/// # Errors
/// [`DropReason::StaleRequest`] when the date is outside the window
/// or fails to parse.
pub fn check_date_skew(
    date_header: &str,
    now: SystemTime,
    max_skew: std::time::Duration,
) -> Result<(), DropReason> {
    let parsed = parse_imf_fixdate(date_header).ok_or(DropReason::StaleRequest)?;
    let delta = if parsed > now {
        parsed
            .duration_since(now)
            .unwrap_or(std::time::Duration::ZERO)
    } else {
        now.duration_since(parsed)
            .unwrap_or(std::time::Duration::ZERO)
    };
    if delta > max_skew {
        Err(DropReason::StaleRequest)
    } else {
        Ok(())
    }
}

/// Parse an RFC 7231 IMF-fixdate `Date` header value back to
/// `SystemTime`. Local parser to keep the dep tree thin (siblings
/// the `format_imf_fixdate` writer in fetchit-fedi).
///
/// Format: `"Sun, 06 Nov 1994 08:49:37 GMT"` — fixed-width.
pub(crate) fn parse_imf_fixdate(s: &str) -> Option<SystemTime> {
    let s = s.trim();
    // Tolerate `GMT` or `UTC`/`+0000` (some emitters drift).
    let s = s
        .strip_suffix(" GMT")
        .or_else(|| s.strip_suffix(" UTC"))
        .or_else(|| s.strip_suffix(" +0000"))?;
    // "Sun, 06 Nov 1994 08:49:37"
    let (_dow, rest) = s.split_once(", ")?;
    let mut parts = rest.split_whitespace();
    let day: u32 = parts.next()?.parse().ok()?;
    let month_name = parts.next()?;
    let year: i64 = parts.next()?.parse().ok()?;
    let hms = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let mut hms_parts = hms.split(':');
    let hour: u64 = hms_parts.next()?.parse().ok()?;
    let minute: u64 = hms_parts.next()?.parse().ok()?;
    let second: u64 = hms_parts.next()?.parse().ok()?;
    if hms_parts.next().is_some() {
        return None;
    }
    let month: u32 = match month_name {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let days = days_from_civil(year, month, day)?;
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second;
    Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs))
}

/// Howard Hinnant's `days_from_civil` — convert `(year, month, day)` to
/// days-since-Unix-epoch. Returns `None` for pre-epoch dates (no
/// fediverse inbox should ever see one).
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
fn days_from_civil(y: i64, m: u32, d: u32) -> Option<u64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y / 400 } else { (y - 399) / 400 };
    let yoe = (y - era * 400) as u64;
    let doy = (153 * (u64::from(if m > 2 { m - 3 } else { m + 9 })) + 2) / 5 + u64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe as i64 - 719_468;
    if days < 0 {
        None
    } else {
        Some(days as u64)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::http::{HeaderName, HeaderValue};

    fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            let name = HeaderName::from_bytes(k.as_bytes()).unwrap();
            m.insert(name, HeaderValue::from_str(v).unwrap());
        }
        m
    }

    #[test]
    fn parse_rfc9421_keyid_extracts_url() {
        let input = r#"sig1=("@method" "@target-uri" "host" "date" "content-digest");created=783000000;keyid="https://etchit.io/actors/josh#main-key";alg="rsa-v1_5-sha256""#;
        assert_eq!(
            parse_rfc9421_keyid(input).as_deref(),
            Some("https://etchit.io/actors/josh#main-key")
        );
    }

    #[test]
    fn parse_rfc9421_keyid_returns_none_when_absent() {
        let input = r#"sig1=("@method");created=0;alg="x""#;
        assert!(parse_rfc9421_keyid(input).is_none());
    }

    #[test]
    fn reconstruct_target_uri_uses_host_header() {
        let headers = hm(&[("host", "mastodon.example")]);
        let uri = reconstruct_target_uri(&headers, "/inbox").unwrap();
        assert_eq!(uri, "https://mastodon.example/inbox");
    }

    #[test]
    fn reconstruct_target_uri_honours_x_forwarded_host() {
        let headers = hm(&[
            ("host", "internal.lb"),
            ("x-forwarded-host", "mastodon.example:8443"),
        ]);
        let uri = reconstruct_target_uri(&headers, "/inbox").unwrap();
        assert_eq!(uri, "https://mastodon.example:8443/inbox");
    }

    #[test]
    fn reconstruct_target_uri_honours_x_forwarded_proto() {
        let headers = hm(&[("host", "mastodon.example"), ("x-forwarded-proto", "https")]);
        let uri = reconstruct_target_uri(&headers, "/inbox").unwrap();
        assert!(uri.starts_with("https://"));
    }

    #[test]
    fn reconstruct_target_uri_missing_host_errors() {
        let headers = hm(&[]);
        let err = reconstruct_target_uri(&headers, "/inbox").unwrap_err();
        assert!(matches!(err, DropReason::MissingHeader("host")));
    }

    #[test]
    fn build_request_target_is_lowercase_post_path() {
        let headers = hm(&[]);
        assert_eq!(
            build_request_target(&headers, "/inbox/users/alice"),
            "post /inbox/users/alice"
        );
    }

    #[test]
    fn extract_context_detects_rfc9421_via_signature_input() {
        let headers = hm(&[
            ("host", "mastodon.example"),
            ("date", "Sun, 06 Nov 1994 08:49:37 GMT"),
            ("content-digest", "sha-256=:abc:"),
            (
                "signature-input",
                r#"sig1=("@method");created=0;keyid="https://etchit.io/actors/josh#main-key";alg="rsa-v1_5-sha256""#,
            ),
            ("signature", "sig1=:AAA:"),
        ]);
        let ctx = extract_inbox_signature_context(&headers, "/inbox").unwrap();
        assert_eq!(ctx.scheme, SignatureScheme::Rfc9421);
        assert_eq!(ctx.key_id, "https://etchit.io/actors/josh#main-key");
        assert_eq!(ctx.target_uri, "https://mastodon.example/inbox");
        assert!(ctx.request_target.is_empty());
    }

    #[test]
    fn extract_context_detects_cavage_without_signature_input() {
        let headers = hm(&[
            ("host", "mastodon.example"),
            ("date", "Sun, 06 Nov 1994 08:49:37 GMT"),
            ("digest", "SHA-256=abc"),
            (
                "signature",
                r#"keyId="https://example.com/actors/alice#main-key",algorithm="rsa-sha256",headers="(request-target) host date digest",signature="AAA""#,
            ),
        ]);
        let ctx = extract_inbox_signature_context(&headers, "/inbox").unwrap();
        assert_eq!(ctx.scheme, SignatureScheme::Cavage);
        assert_eq!(ctx.key_id, "https://example.com/actors/alice#main-key");
        assert_eq!(ctx.request_target, "post /inbox");
        assert!(ctx.target_uri.is_empty());
    }

    #[test]
    fn extract_context_missing_signature_errors() {
        let headers = hm(&[("host", "h"), ("date", "d"), ("digest", "x")]);
        let err = extract_inbox_signature_context(&headers, "/inbox").unwrap_err();
        assert!(matches!(err, DropReason::MissingHeader("signature")));
    }

    #[test]
    fn extract_context_missing_date_errors() {
        let headers = hm(&[("host", "h"), ("signature", "x"), ("digest", "x")]);
        let err = extract_inbox_signature_context(&headers, "/inbox").unwrap_err();
        assert!(matches!(err, DropReason::MissingHeader("date")));
    }

    #[test]
    fn extract_context_rfc9421_missing_content_digest_errors() {
        let headers = hm(&[
            ("host", "h"),
            ("date", "d"),
            (
                "signature-input",
                r#"sig1=();keyid="x";alg="rsa-v1_5-sha256""#,
            ),
            ("signature", "sig1=:AAA:"),
        ]);
        let err = extract_inbox_signature_context(&headers, "/inbox").unwrap_err();
        assert!(matches!(err, DropReason::MissingHeader("content-digest")));
    }

    #[test]
    fn extract_context_cavage_missing_digest_errors() {
        let headers = hm(&[
            ("host", "h"),
            ("date", "d"),
            ("signature", r#"keyId="x",headers="host",signature="AAA""#),
        ]);
        let err = extract_inbox_signature_context(&headers, "/inbox").unwrap_err();
        assert!(matches!(err, DropReason::MissingHeader("digest")));
    }

    #[test]
    fn parse_imf_fixdate_round_trips_known_value() {
        let s = "Sun, 06 Nov 1994 08:49:37 GMT";
        let t = parse_imf_fixdate(s).unwrap();
        let secs = t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(secs, 784_111_777);
    }

    #[test]
    fn parse_imf_fixdate_handles_leap_year_feb_29() {
        // 2024-02-29 12:00:00 UTC — mirrors the fetchit-fedi golden
        // pin from Stage 2.2.
        let t = parse_imf_fixdate("Thu, 29 Feb 2024 12:00:00 GMT").unwrap();
        let secs = t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(secs, 1_709_208_000);
    }

    #[test]
    fn parse_imf_fixdate_rejects_garbage() {
        assert!(parse_imf_fixdate("nonsense").is_none());
        assert!(parse_imf_fixdate("Sun, 06 Nov 1994 08:49:37").is_none()); // missing tz
        assert!(parse_imf_fixdate("Sun, 32 Nov 1994 08:49:37 GMT").is_none()); // bad day
        assert!(parse_imf_fixdate("Sun, 06 Xxx 1994 08:49:37 GMT").is_none()); // bad month
    }

    #[test]
    fn check_date_skew_allows_within_window() {
        let signed_at = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(784_111_777);
        // Receiver is 1 minute ahead; well inside ±5 min.
        let now = signed_at + std::time::Duration::from_secs(60);
        check_date_skew(
            "Sun, 06 Nov 1994 08:49:37 GMT",
            now,
            std::time::Duration::from_secs(300),
        )
        .expect("within window");
    }

    #[test]
    fn check_date_skew_rejects_outside_window() {
        let signed_at = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(784_111_777);
        // 6 minutes ahead — past the ±5 min window.
        let now = signed_at + std::time::Duration::from_secs(6 * 60);
        let err = check_date_skew(
            "Sun, 06 Nov 1994 08:49:37 GMT",
            now,
            std::time::Duration::from_secs(300),
        )
        .unwrap_err();
        assert!(matches!(err, DropReason::StaleRequest));
    }

    #[test]
    fn check_date_skew_rejects_unparseable() {
        let now = SystemTime::now();
        let err = check_date_skew(
            "this is not a date",
            now,
            std::time::Duration::from_secs(300),
        )
        .unwrap_err();
        assert!(matches!(err, DropReason::StaleRequest));
    }
}
