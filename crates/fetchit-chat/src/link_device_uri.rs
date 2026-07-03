//! `fetchit://link/v1/<token>?r=<relay>[&r=<relay>...]#k=<key_b64url>` —
//! the compact QR pointer a NEW device shows to link itself to an account.
//!
//! A [`LinkDeviceOffer`](crate::link_device::LinkDeviceOffer) carries two
//! post-quantum public keys (~3 KB), far more than a scannable QR holds. So,
//! exactly as the compact group invite does, the offer is sealed with
//! ChaCha20-Poly1305 and published to a relay under an opaque `token`; this
//! small pointer is what the QR actually encodes. The existing device fetches
//! the ciphertext by `token`, decrypts it with `key`, and recovers the offer.
//!
//! `key` rides in the URI **fragment**, never the query: a fragment is
//! conventionally client-only, so the seal key is less likely to be logged by
//! an intermediary, and the existing device never transmits it to the relay
//! (it fetches by `token` and decrypts locally). The relay therefore only ever
//! holds opaque ciphertext — the same blind-relay posture as the group invite.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use crate::chat_crypto::AEAD_KEY_LEN;
use crate::pair_uri::{normalize_relay, validate_relay, MAX_RELAYS, MAX_URI_LEN};

/// URI scheme, host, and version path segments.
const SCHEME: &str = "fetchit";
const HOST_SEGMENT: &str = "link";
const VERSION_SEGMENT: &str = "v1";

/// Decoded token length bounds. The token is the relay's opaque storage key;
/// 16..=48 random bytes is an unguessable capability without bloating the QR.
const TOKEN_MIN_BYTES: usize = 16;
const TOKEN_MAX_BYTES: usize = 48;

/// Errors from [`emit_link_device_uri`] and [`parse_link_device_uri`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LinkDeviceUriError {
    /// URI exceeds `MAX_URI_LEN` bytes.
    #[error("link URI exceeds {MAX_URI_LEN} bytes")]
    TooLong,

    /// Scheme, host, or path shape is not `fetchit://link/<version>/<token>`.
    #[error("link URI scheme/host/path is malformed")]
    BadUri,

    /// The version path segment is not `VERSION_SEGMENT`.
    #[error("link URI version segment must be {VERSION_SEGMENT}")]
    BadVersion,

    /// Token is not base64url or decodes outside the length bounds.
    #[error("link token must be base64url of {TOKEN_MIN_BYTES}..={TOKEN_MAX_BYTES} bytes")]
    InvalidToken,

    /// The `#k=` fragment is absent.
    #[error("link URI must carry a key in the fragment (#k=...)")]
    MissingKey,

    /// The key is not base64url of exactly `AEAD_KEY_LEN` bytes.
    #[error("link key must be base64url of {AEAD_KEY_LEN} bytes")]
    InvalidKey,

    /// No `r` query parameters present.
    #[error("link URI must contain at least one relay")]
    NoRelays,

    /// More than `MAX_RELAYS` `r` parameters.
    #[error("link URI must not contain more than {MAX_RELAYS} relays")]
    TooManyRelays,

    /// A relay URL failed validation.
    #[error("invalid relay URL: {0}")]
    InvalidRelay(String),
}

/// Parsed result from [`parse_link_device_uri`]. The `key` is the AEAD seal
/// secret recovered from the fragment, wrapped in [`Zeroizing`]; its `Debug`
/// is redacted so it never lands in a log line.
#[derive(Clone, PartialEq, Eq)]
pub struct ParsedLinkDeviceUri {
    /// Base64url relay-storage token addressing the sealed offer blob.
    pub token: String,
    /// Normalized, deduplicated relay URLs in priority order.
    pub relays: Vec<String>,
    /// 32-byte ChaCha20-Poly1305 key that opens the sealed offer.
    pub key: Zeroizing<[u8; AEAD_KEY_LEN]>,
}

impl std::fmt::Debug for ParsedLinkDeviceUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedLinkDeviceUri")
            .field("token", &self.token)
            .field("relays", &self.relays)
            .field("key", &"<redacted>")
            .finish()
    }
}

/// Emit `fetchit://link/v1/<token>?r=<relay>...#k=<key>`.
///
/// `token` must be base64url of `TOKEN_MIN_BYTES..=TOKEN_MAX_BYTES`.
/// `relays` must be 1..=`MAX_RELAYS` valid http/https URLs. `key` is the
/// 32-byte AEAD seal key, emitted base64url in the fragment.
///
/// # Errors
/// A [`LinkDeviceUriError`] variant when the token, key, relays, or total
/// length fail validation.
pub fn emit_link_device_uri(
    token: &str,
    relays: &[String],
    key: &[u8; AEAD_KEY_LEN],
) -> Result<String, LinkDeviceUriError> {
    validate_token(token)?;
    if relays.is_empty() {
        return Err(LinkDeviceUriError::NoRelays);
    }
    if relays.len() > MAX_RELAYS {
        return Err(LinkDeviceUriError::TooManyRelays);
    }
    for relay in relays {
        validate_relay(relay).map_err(|e| LinkDeviceUriError::InvalidRelay(e.to_string()))?;
    }

    let mut url = Url::parse(&format!(
        "{SCHEME}://{HOST_SEGMENT}/{VERSION_SEGMENT}/{token}"
    ))
    .map_err(|_| LinkDeviceUriError::BadUri)?;
    {
        let mut pairs = url.query_pairs_mut();
        for relay in relays {
            pairs.append_pair("r", relay);
        }
    }
    url.set_fragment(Some(&format!("k={}", B64URL.encode(key))));

    let s = url.to_string();
    if s.len() > MAX_URI_LEN {
        return Err(LinkDeviceUriError::TooLong);
    }
    Ok(s)
}

/// Parse `fetchit://link/v1/<token>?r=<relay>...#k=<key>`.
///
/// Enforces total length, scheme/host, the `v1` version segment, a valid
/// token, 1..=`MAX_RELAYS` relays (validated + normalized + deduped exactly as
/// the pair URI), and a `#k=` fragment decoding to a 32-byte key.
///
/// # Errors
/// A [`LinkDeviceUriError`] variant per the rules above.
pub fn parse_link_device_uri(uri: &str) -> Result<ParsedLinkDeviceUri, LinkDeviceUriError> {
    if uri.len() > MAX_URI_LEN {
        return Err(LinkDeviceUriError::TooLong);
    }

    let parsed = Url::parse(uri).map_err(|_| LinkDeviceUriError::BadUri)?;
    if parsed.scheme() != SCHEME {
        return Err(LinkDeviceUriError::BadUri);
    }
    if parsed.host_str().unwrap_or("") != HOST_SEGMENT {
        return Err(LinkDeviceUriError::BadUri);
    }
    let path = parsed.path();
    let rest = path.strip_prefix('/').unwrap_or(path);
    let (version, token) = rest.split_once('/').ok_or(LinkDeviceUriError::BadUri)?;
    if version != VERSION_SEGMENT {
        return Err(LinkDeviceUriError::BadVersion);
    }
    validate_token(token)?;

    let raw_relays: Vec<String> = parsed
        .query_pairs()
        .filter(|(k, _)| k == "r")
        .map(|(_, v)| v.into_owned())
        .collect();
    if raw_relays.is_empty() {
        return Err(LinkDeviceUriError::NoRelays);
    }
    if raw_relays.len() > MAX_RELAYS {
        return Err(LinkDeviceUriError::TooManyRelays);
    }
    let mut relays: Vec<String> = Vec::with_capacity(raw_relays.len());
    for raw in &raw_relays {
        validate_relay(raw).map_err(|e| LinkDeviceUriError::InvalidRelay(e.to_string()))?;
        let normalized =
            normalize_relay(raw).map_err(|e| LinkDeviceUriError::InvalidRelay(e.to_string()))?;
        if !relays.contains(&normalized) {
            relays.push(normalized);
        }
    }

    let key = parse_fragment_key(parsed.fragment())?;

    Ok(ParsedLinkDeviceUri {
        token: token.to_owned(),
        relays,
        key,
    })
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn validate_token(token: &str) -> Result<(), LinkDeviceUriError> {
    let decoded = B64URL
        .decode(token)
        .map_err(|_| LinkDeviceUriError::InvalidToken)?;
    if (TOKEN_MIN_BYTES..=TOKEN_MAX_BYTES).contains(&decoded.len()) {
        Ok(())
    } else {
        Err(LinkDeviceUriError::InvalidToken)
    }
}

fn parse_fragment_key(
    fragment: Option<&str>,
) -> Result<Zeroizing<[u8; AEAD_KEY_LEN]>, LinkDeviceUriError> {
    let frag = fragment.ok_or(LinkDeviceUriError::MissingKey)?;
    let raw = frag
        .strip_prefix("k=")
        .ok_or(LinkDeviceUriError::MissingKey)?;
    let bytes = Zeroizing::new(
        B64URL
            .decode(raw)
            .map_err(|_| LinkDeviceUriError::InvalidKey)?,
    );
    let key: [u8; AEAD_KEY_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| LinkDeviceUriError::InvalidKey)?;
    Ok(Zeroizing::new(key))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn token() -> String {
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
        let uri = emit_link_device_uri(&token(), &relays(&[RELAY_A]), &key()).unwrap();
        let parsed = parse_link_device_uri(&uri).unwrap();
        assert_eq!(parsed.token, token());
        assert_eq!(parsed.relays, relays(&[RELAY_A]));
        assert_eq!(*parsed.key, key());
    }

    #[test]
    fn round_trip_multi_relay_dedup() {
        let uri =
            emit_link_device_uri(&token(), &relays(&[RELAY_A, RELAY_B, RELAY_A]), &key()).unwrap();
        let parsed = parse_link_device_uri(&uri).unwrap();
        assert_eq!(parsed.relays, relays(&[RELAY_A, RELAY_B]));
    }

    #[test]
    fn carries_the_v1_version_segment() {
        let uri = emit_link_device_uri(&token(), &relays(&[RELAY_A]), &key()).unwrap();
        assert!(
            uri.starts_with("fetchit://link/v1/"),
            "unexpected shape: {uri}"
        );
    }

    #[test]
    fn key_rides_the_fragment_not_the_query() {
        let uri = emit_link_device_uri(&token(), &relays(&[RELAY_A]), &key()).unwrap();
        let (before_frag, frag) = uri.split_once('#').expect("uri has a fragment");
        assert!(frag.starts_with("k="), "key must be in the fragment");
        assert!(
            !before_frag.contains("k="),
            "key must not leak into the query/path: {before_frag}"
        );
    }

    #[test]
    fn pointer_is_small() {
        let uri = emit_link_device_uri(&token(), &relays(&[RELAY_A]), &key()).unwrap();
        assert!(
            uri.len() < 200,
            "pointer should be QR-sized, got {}",
            uri.len()
        );
    }

    #[test]
    fn reject_missing_key_fragment() {
        let uri = format!("fetchit://link/v1/{}?r={RELAY_A}", token());
        assert_eq!(
            parse_link_device_uri(&uri),
            Err(LinkDeviceUriError::MissingKey)
        );
    }

    #[test]
    fn reject_wrong_length_key() {
        let short = B64URL.encode([1u8; 16]);
        let uri = format!("fetchit://link/v1/{}?r={RELAY_A}#k={short}", token());
        assert_eq!(
            parse_link_device_uri(&uri),
            Err(LinkDeviceUriError::InvalidKey)
        );
    }

    #[test]
    fn reject_non_base64_key() {
        let uri = format!("fetchit://link/v1/{}?r={RELAY_A}#k=not*base64*", token());
        assert_eq!(
            parse_link_device_uri(&uri),
            Err(LinkDeviceUriError::InvalidKey)
        );
    }

    #[test]
    fn reject_short_token_on_emit() {
        let short = B64URL.encode([1u8; 8]);
        assert_eq!(
            emit_link_device_uri(&short, &relays(&[RELAY_A]), &key()),
            Err(LinkDeviceUriError::InvalidToken)
        );
    }

    #[test]
    fn reject_non_base64_token_on_parse() {
        let uri = format!(
            "fetchit://link/v1/not*a*token?r={RELAY_A}#k={}",
            B64URL.encode(key())
        );
        assert_eq!(
            parse_link_device_uri(&uri),
            Err(LinkDeviceUriError::InvalidToken)
        );
    }

    #[test]
    fn reject_zero_relays() {
        assert_eq!(
            emit_link_device_uri(&token(), &[], &key()),
            Err(LinkDeviceUriError::NoRelays)
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
            emit_link_device_uri(&token(), &five, &key()),
            Err(LinkDeviceUriError::TooManyRelays)
        );
    }

    #[test]
    fn reject_bad_relay_scheme() {
        // A non-http/https relay scheme must be rejected by validate_relay.
        assert!(matches!(
            emit_link_device_uri(&token(), &relays(&["ftp://relay.io"]), &key()),
            Err(LinkDeviceUriError::InvalidRelay(_))
        ));
    }

    #[test]
    fn parse_rejects_wrong_scheme() {
        let uri = format!(
            "x0x://link/v1/{}?r={RELAY_A}#k={}",
            token(),
            B64URL.encode(key())
        );
        assert_eq!(parse_link_device_uri(&uri), Err(LinkDeviceUriError::BadUri));
    }

    #[test]
    fn parse_rejects_wrong_host_segment() {
        let uri = format!(
            "fetchit://pair/v1/{}?r={RELAY_A}#k={}",
            token(),
            B64URL.encode(key())
        );
        assert_eq!(parse_link_device_uri(&uri), Err(LinkDeviceUriError::BadUri));
    }

    #[test]
    fn parse_rejects_wrong_version_segment() {
        let uri = format!(
            "fetchit://link/v2/{}?r={RELAY_A}#k={}",
            token(),
            B64URL.encode(key())
        );
        assert_eq!(
            parse_link_device_uri(&uri),
            Err(LinkDeviceUriError::BadVersion)
        );
    }

    #[test]
    fn debug_redacts_the_key() {
        let uri = emit_link_device_uri(&token(), &relays(&[RELAY_A]), &key()).unwrap();
        let parsed = parse_link_device_uri(&uri).unwrap();
        let shown = format!("{parsed:?}");
        assert!(shown.contains("<redacted>"));
        assert!(
            !shown.contains("CQkJ"),
            "key bytes must not appear in Debug"
        );
    }
}
