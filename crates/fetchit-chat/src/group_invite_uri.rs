//! QR-sized compact group-invite pointer URI — emit and parse.
//!
//! `x0x://ginvite/<token>?r=<relay>[&r=<relay>...]#k=<key_b64url>`
//!
//! x0xd's `x0x://invite/<base64>` link inlines the whole group bootstrap
//! (every member's ML-KEM key + `TreeKEM` state), so it grows with
//! membership (~25 KB at two members). This pointer replaces it: the big
//! invite is sealed with ChaCha20-Poly1305 and published to a relay under
//! `token`; the joiner fetches the ciphertext, decrypts it with `key`,
//! and feeds the recovered link to the existing group-join path.
//!
//! `key` rides in the URI **fragment**, never the query: a fragment is
//! conventionally client-only, so the secret is less likely to be logged
//! by an intermediary, and the joiner never transmits it to the relay
//! (it fetches by `token` and decrypts locally). The relay therefore only
//! ever holds opaque ciphertext. Design:
//! `docs/superpowers/specs/2026-06-25-compact-group-invite-design.md`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use crate::chat_crypto::AEAD_KEY_LEN;
use crate::pair_uri::{normalize_relay, validate_relay, MAX_RELAYS, MAX_URI_LEN};

/// URI scheme and host segment.
const SCHEME: &str = "x0x";
const HOST_SEGMENT: &str = "ginvite";

/// Decoded token length bounds. The token is the relay's opaque storage
/// key; 16..=48 random bytes is an unguessable capability without bloating
/// the URI.
const TOKEN_MIN_BYTES: usize = 16;
const TOKEN_MAX_BYTES: usize = 48;

/// Errors from [`emit_ginvite_uri`] and [`parse_ginvite_uri`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GinviteUriError {
    /// URI exceeds `MAX_URI_LEN` bytes.
    #[error("ginvite URI exceeds {MAX_URI_LEN} bytes")]
    TooLong,

    /// Token is not base64url or decodes outside the length bounds.
    #[error("ginvite token must be base64url of {TOKEN_MIN_BYTES}..={TOKEN_MAX_BYTES} bytes")]
    InvalidToken,

    /// The `#k=` fragment is absent.
    #[error("ginvite URI must carry a key in the fragment (#k=...)")]
    MissingKey,

    /// The key is not base64url of exactly `AEAD_KEY_LEN` bytes.
    #[error("ginvite key must be base64url of {AEAD_KEY_LEN} bytes")]
    InvalidKey,

    /// No `r` query parameters present.
    #[error("ginvite URI must contain at least one relay")]
    NoRelays,

    /// More than `MAX_RELAYS` `r` parameters.
    #[error("ginvite URI must not contain more than {MAX_RELAYS} relays")]
    TooManyRelays,

    /// A relay URL failed validation.
    #[error("invalid relay URL: {0}")]
    InvalidRelay(String),
}

/// Parsed result from [`parse_ginvite_uri`]. The `key` is the AEAD secret
/// recovered from the fragment, wrapped in [`Zeroizing`]; its `Debug` is
/// redacted so it never lands in a log line.
#[derive(Clone, PartialEq, Eq)]
pub struct ParsedGinviteUri {
    /// Base64url relay-storage token addressing the sealed blob.
    pub token: String,
    /// Normalized, deduplicated relay URLs in priority order.
    pub relays: Vec<String>,
    /// 32-byte ChaCha20-Poly1305 key that opens the sealed blob.
    pub key: Zeroizing<[u8; AEAD_KEY_LEN]>,
}

impl std::fmt::Debug for ParsedGinviteUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedGinviteUri")
            .field("token", &self.token)
            .field("relays", &self.relays)
            .field("key", &"<redacted>")
            .finish()
    }
}

/// Emit `x0x://ginvite/<token>?r=<relay>...#k=<key>`.
///
/// `token` must be base64url of `TOKEN_MIN_BYTES..=TOKEN_MAX_BYTES`.
/// `relays` must be 1..=`MAX_RELAYS` valid http/https URLs. `key` is the
/// 32-byte AEAD key, emitted base64url in the fragment.
///
/// # Errors
/// A [`GinviteUriError`] variant when the token, key, relays, or total
/// length fail validation.
pub fn emit_ginvite_uri(
    token: &str,
    relays: &[String],
    key: &[u8; AEAD_KEY_LEN],
) -> Result<String, GinviteUriError> {
    validate_token(token)?;
    if relays.is_empty() {
        return Err(GinviteUriError::NoRelays);
    }
    if relays.len() > MAX_RELAYS {
        return Err(GinviteUriError::TooManyRelays);
    }
    for relay in relays {
        validate_relay(relay).map_err(|e| GinviteUriError::InvalidRelay(e.to_string()))?;
    }

    let mut url =
        Url::parse(&format!("x0x://ginvite/{token}")).map_err(|_| GinviteUriError::InvalidToken)?;
    {
        let mut pairs = url.query_pairs_mut();
        for relay in relays {
            pairs.append_pair("r", relay);
        }
    }
    url.set_fragment(Some(&format!("k={}", B64URL.encode(key))));

    let s = url.to_string();
    if s.len() > MAX_URI_LEN {
        return Err(GinviteUriError::TooLong);
    }
    Ok(s)
}

/// Parse `x0x://ginvite/<token>?r=<relay>...#k=<key>`.
///
/// Enforces total length, scheme/host, a valid token, 1..=`MAX_RELAYS`
/// relays (validated + normalized + deduped exactly as the pair URI), and
/// a `#k=` fragment decoding to a 32-byte key.
///
/// # Errors
/// A [`GinviteUriError`] variant per the rules above.
pub fn parse_ginvite_uri(uri: &str) -> Result<ParsedGinviteUri, GinviteUriError> {
    if uri.len() > MAX_URI_LEN {
        return Err(GinviteUriError::TooLong);
    }

    let parsed = Url::parse(uri).map_err(|_| GinviteUriError::InvalidToken)?;
    if parsed.scheme() != SCHEME {
        return Err(GinviteUriError::InvalidToken);
    }
    if parsed.host_str().unwrap_or("") != HOST_SEGMENT {
        return Err(GinviteUriError::InvalidToken);
    }
    let token = parsed.path().trim_start_matches('/').to_owned();
    validate_token(&token)?;

    let raw_relays: Vec<String> = parsed
        .query_pairs()
        .filter(|(k, _)| k == "r")
        .map(|(_, v)| v.into_owned())
        .collect();
    if raw_relays.is_empty() {
        return Err(GinviteUriError::NoRelays);
    }
    if raw_relays.len() > MAX_RELAYS {
        return Err(GinviteUriError::TooManyRelays);
    }
    let mut relays: Vec<String> = Vec::with_capacity(raw_relays.len());
    for raw in &raw_relays {
        validate_relay(raw).map_err(|e| GinviteUriError::InvalidRelay(e.to_string()))?;
        let normalized =
            normalize_relay(raw).map_err(|e| GinviteUriError::InvalidRelay(e.to_string()))?;
        if !relays.contains(&normalized) {
            relays.push(normalized);
        }
    }

    let key = parse_fragment_key(parsed.fragment())?;

    Ok(ParsedGinviteUri { token, relays, key })
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn validate_token(token: &str) -> Result<(), GinviteUriError> {
    let decoded = B64URL
        .decode(token)
        .map_err(|_| GinviteUriError::InvalidToken)?;
    if (TOKEN_MIN_BYTES..=TOKEN_MAX_BYTES).contains(&decoded.len()) {
        Ok(())
    } else {
        Err(GinviteUriError::InvalidToken)
    }
}

fn parse_fragment_key(
    fragment: Option<&str>,
) -> Result<Zeroizing<[u8; AEAD_KEY_LEN]>, GinviteUriError> {
    let frag = fragment.ok_or(GinviteUriError::MissingKey)?;
    let raw = frag.strip_prefix("k=").ok_or(GinviteUriError::MissingKey)?;
    let bytes = Zeroizing::new(
        B64URL
            .decode(raw)
            .map_err(|_| GinviteUriError::InvalidKey)?,
    );
    let key: [u8; AEAD_KEY_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| GinviteUriError::InvalidKey)?;
    Ok(Zeroizing::new(key))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn token() -> String {
        // 32 random-ish bytes -> base64url no pad (43 chars).
        B64URL.encode([7u8; 32])
    }
    fn key() -> [u8; AEAD_KEY_LEN] {
        [9u8; AEAD_KEY_LEN]
    }
    fn relays(v: &[&str]) -> Vec<String> {
        v.iter().map(std::string::ToString::to_string).collect()
    }
    const RELAY_A: &str = "https://relay-a.example.com";
    const RELAY_B: &str = "https://relay-b.example.com";

    #[test]
    fn round_trip_one_relay() {
        let uri = emit_ginvite_uri(&token(), &relays(&[RELAY_A]), &key()).unwrap();
        let parsed = parse_ginvite_uri(&uri).unwrap();
        assert_eq!(parsed.token, token());
        assert_eq!(parsed.relays, relays(&[RELAY_A]));
        assert_eq!(*parsed.key, key());
    }

    #[test]
    fn round_trip_multi_relay_dedup() {
        let uri =
            emit_ginvite_uri(&token(), &relays(&[RELAY_A, RELAY_B, RELAY_A]), &key()).unwrap();
        let parsed = parse_ginvite_uri(&uri).unwrap();
        assert_eq!(parsed.relays, relays(&[RELAY_A, RELAY_B]));
    }

    #[test]
    fn key_rides_the_fragment_not_the_query() {
        let uri = emit_ginvite_uri(&token(), &relays(&[RELAY_A]), &key()).unwrap();
        let (before_frag, frag) = uri.split_once('#').expect("uri has a fragment");
        assert!(frag.starts_with("k="), "key must be in the fragment");
        assert!(
            !before_frag.contains("k="),
            "key must not leak into the query/path: {before_frag}"
        );
    }

    #[test]
    fn pointer_is_small() {
        let uri = emit_ginvite_uri(&token(), &relays(&[RELAY_A]), &key()).unwrap();
        assert!(
            uri.len() < 200,
            "pointer should be QR-sized, got {}",
            uri.len()
        );
    }

    #[test]
    fn reject_missing_key_fragment() {
        let uri = format!("x0x://ginvite/{}?r={RELAY_A}", token());
        assert_eq!(parse_ginvite_uri(&uri), Err(GinviteUriError::MissingKey));
    }

    #[test]
    fn reject_wrong_length_key() {
        // 16-byte key instead of 32.
        let short = B64URL.encode([1u8; 16]);
        let uri = format!("x0x://ginvite/{}?r={RELAY_A}#k={short}", token());
        assert_eq!(parse_ginvite_uri(&uri), Err(GinviteUriError::InvalidKey));
    }

    #[test]
    fn reject_non_base64_key() {
        let uri = format!("x0x://ginvite/{}?r={RELAY_A}#k=not*base64*", token());
        assert_eq!(parse_ginvite_uri(&uri), Err(GinviteUriError::InvalidKey));
    }

    #[test]
    fn reject_short_token() {
        let short = B64URL.encode([1u8; 8]); // 8 bytes < 16
        assert_eq!(
            emit_ginvite_uri(&short, &relays(&[RELAY_A]), &key()),
            Err(GinviteUriError::InvalidToken)
        );
    }

    #[test]
    fn reject_non_base64_token_on_parse() {
        let uri = format!(
            "x0x://ginvite/not*a*token?r={RELAY_A}#k={}",
            B64URL.encode(key())
        );
        assert_eq!(parse_ginvite_uri(&uri), Err(GinviteUriError::InvalidToken));
    }

    #[test]
    fn reject_zero_relays() {
        assert_eq!(
            emit_ginvite_uri(&token(), &[], &key()),
            Err(GinviteUriError::NoRelays)
        );
    }

    #[test]
    fn reject_too_many_relays() {
        let five = relays(&[
            "https://a.io",
            "https://b.io",
            "https://c.io",
            "https://d.io",
            "https://e.io",
        ]);
        assert_eq!(
            emit_ginvite_uri(&token(), &five, &key()),
            Err(GinviteUriError::TooManyRelays)
        );
    }

    #[test]
    fn reject_bad_relay_scheme() {
        assert!(matches!(
            emit_ginvite_uri(&token(), &relays(&["ws://relay.io"]), &key()),
            Err(GinviteUriError::InvalidRelay(_))
        ));
    }

    #[test]
    fn parse_rejects_wrong_host_segment() {
        let uri = format!(
            "x0x://pair/{}?r={RELAY_A}#k={}",
            token(),
            B64URL.encode(key())
        );
        assert_eq!(parse_ginvite_uri(&uri), Err(GinviteUriError::InvalidToken));
    }

    #[test]
    fn debug_redacts_the_key() {
        let uri = emit_ginvite_uri(&token(), &relays(&[RELAY_A]), &key()).unwrap();
        let parsed = parse_ginvite_uri(&uri).unwrap();
        let shown = format!("{parsed:?}");
        assert!(shown.contains("<redacted>"));
        assert!(
            !shown.contains("CQkJ"),
            "key bytes must not appear in Debug"
        );
    }
}
