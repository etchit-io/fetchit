//! QR-sized pair pointer URI — emit and parse.
//!
//! `x0x://pair/<agent_id_hex>?r=<relay>[&r=<relay>...]`
//!
//! Replaces the ~12 KB v2 share-card URI with a pointer small enough to
//! fit in a QR code. The receiver fetches the signer's
//! [`fetchit_relay_proto::pair_record::PairRecordV1`] from one of the
//! advertised relays via
//! [`crate::pair::fetch_pair_record_by_id`], verifies it, and persists a
//! [`crate::messages::StoredContactCard`].

use thiserror::Error;
use url::Url;

/// URI scheme and host segment.
const SCHEME: &str = "x0x";
const HOST_SEGMENT: &str = "pair";

/// Maximum total URI length. QR codes with > 512 bytes of alphanumeric
/// data require a version that most phone cameras refuse to scan.
const MAX_URI_LEN: usize = 512;

/// Maximum relay URL byte length (mirrors the pair-record spec).
const MAX_RELAY_LEN: usize = 256;

/// Maximum number of relay entries per URI (mirrors the pair-record spec).
const MAX_RELAYS: usize = 4;

/// Errors from [`emit_pair_uri`] and [`parse_pair_uri`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PairUriError {
    /// URI exceeds `MAX_URI_LEN` bytes.
    #[error("pair URI exceeds {MAX_URI_LEN} bytes")]
    TooLong,

    /// `agent_id_hex` is not strictly lowercase 64-hex.
    #[error("agent_id_hex must be lowercase 64-hex")]
    InvalidAgentId,

    /// No `r` query parameters present.
    #[error("pair URI must contain at least one relay")]
    NoRelays,

    /// More than `MAX_RELAYS` `r` parameters.
    #[error("pair URI must not contain more than {MAX_RELAYS} relays")]
    TooManyRelays,

    /// A relay URL failed validation (bad scheme, missing host, userinfo,
    /// or exceeds `MAX_RELAY_LEN`).
    #[error("invalid relay URL: {0}")]
    InvalidRelay(String),
}

/// Parsed result from [`parse_pair_uri`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPairUri {
    /// Lowercase 64-hex agent id.
    pub agent_id_hex: String,
    /// Normalized, deduplicated relay URLs in priority order.
    pub relays: Vec<String>,
}

/// Emit a `x0x://pair/<agent_id_hex>?r=<relay>[&r=<relay>...]` URI.
///
/// `agent_id_hex` must be lowercase 64-hex. `relays` must be 1..=4
/// entries. Percent-encoding of the relay values is handled by the
/// `url` crate.
///
/// # Errors
///
/// [`PairUriError::InvalidAgentId`] when `agent_id_hex` is not 64
/// lowercase hex chars. [`PairUriError::NoRelays`] /
/// [`PairUriError::TooManyRelays`] for out-of-range relay counts.
/// [`PairUriError::InvalidRelay`] when a relay fails the same
/// validation as [`parse_pair_uri`] applies on the read side.
/// [`PairUriError::TooLong`] when the resulting URI exceeds 512 bytes.
pub fn emit_pair_uri(agent_id_hex: &str, relays: &[String]) -> Result<String, PairUriError> {
    validate_agent_id_hex(agent_id_hex)?;
    if relays.is_empty() {
        return Err(PairUriError::NoRelays);
    }
    if relays.len() > MAX_RELAYS {
        return Err(PairUriError::TooManyRelays);
    }
    for relay in relays {
        validate_relay(relay)?;
    }

    let mut url = Url::parse(&format!("x0x://pair/{agent_id_hex}"))
        .map_err(|e| PairUriError::InvalidRelay(format!("failed to construct base URI: {e}")))?;
    {
        let mut pairs = url.query_pairs_mut();
        for relay in relays {
            pairs.append_pair("r", relay);
        }
    }
    let s = url.to_string();
    if s.len() > MAX_URI_LEN {
        return Err(PairUriError::TooLong);
    }
    Ok(s)
}

/// Parse a `x0x://pair/<agent_id_hex>?r=<relay>[&r=<relay>...]` URI.
///
/// Enforces:
/// - Total URI length <= 512 bytes.
/// - Scheme `x0x`, path segment `pair/<agent_id_hex>`.
/// - `agent_id_hex` is lowercase 64-hex.
/// - 1..=4 `r` query params (checked before normalization).
/// - Each relay: http/https, non-empty host, no userinfo, <= 256 bytes.
/// - Normalized (lowercase host, default port stripped, trailing `/`
///   on empty path stripped) and deduplicated preserving first-seen order.
///
/// # Errors
///
/// One of the [`PairUriError`] variants per the spec above.
pub fn parse_pair_uri(uri: &str) -> Result<ParsedPairUri, PairUriError> {
    if uri.len() > MAX_URI_LEN {
        return Err(PairUriError::TooLong);
    }

    let parsed = Url::parse(uri).map_err(|_| PairUriError::InvalidAgentId)?;
    if parsed.scheme() != SCHEME {
        return Err(PairUriError::InvalidAgentId);
    }
    // x0x://pair/<agent_id_hex> — the url crate puts "pair" in host and
    // agent_id_hex as the path segment "/…".
    let host = parsed.host_str().unwrap_or("");
    if host != HOST_SEGMENT {
        return Err(PairUriError::InvalidAgentId);
    }
    let path = parsed.path().trim_start_matches('/');
    let agent_id_hex = path.to_owned();
    validate_agent_id_hex(&agent_id_hex)?;

    // Collect raw relay strings from `r` params. Reject >4 before any
    // normalization (so padding attacks can't smuggle 5 past the cap by
    // making two look alike).
    let raw_relays: Vec<String> = parsed
        .query_pairs()
        .filter(|(k, _)| k == "r")
        .map(|(_, v)| v.into_owned())
        .collect();

    if raw_relays.is_empty() {
        return Err(PairUriError::NoRelays);
    }
    if raw_relays.len() > MAX_RELAYS {
        return Err(PairUriError::TooManyRelays);
    }

    // Validate + normalize each relay.
    let mut relays: Vec<String> = Vec::with_capacity(raw_relays.len());
    for raw in &raw_relays {
        validate_relay(raw)?;
        let normalized = normalize_relay(raw)?;
        // Dedupe: skip if an equivalent (post-normalization) URL was already
        // accepted.
        if !relays.contains(&normalized) {
            relays.push(normalized);
        }
    }

    Ok(ParsedPairUri {
        agent_id_hex,
        relays,
    })
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn validate_agent_id_hex(s: &str) -> Result<(), PairUriError> {
    if s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        Err(PairUriError::InvalidAgentId)
    }
}

fn validate_relay(relay: &str) -> Result<(), PairUriError> {
    if relay.len() > MAX_RELAY_LEN {
        return Err(PairUriError::InvalidRelay(format!(
            "relay URL exceeds {MAX_RELAY_LEN} bytes"
        )));
    }
    let parsed = relay
        .parse::<Url>()
        .map_err(|e| PairUriError::InvalidRelay(format!("URL parse: {e}")))?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(PairUriError::InvalidRelay(format!(
            "relay scheme must be http or https, got {scheme}"
        )));
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err(PairUriError::InvalidRelay("relay has no host".into()));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(PairUriError::InvalidRelay(
            "relay URL must not embed credentials".into(),
        ));
    }
    Ok(())
}

/// Normalize a validated relay URL:
/// - lowercase the host
/// - strip default port (80 for http, 443 for https)
/// - strip a trailing `/` on an empty path
fn normalize_relay(relay: &str) -> Result<String, PairUriError> {
    let mut url = relay
        .parse::<Url>()
        .map_err(|e| PairUriError::InvalidRelay(format!("URL parse: {e}")))?;

    // Lowercase the host.
    let lower_host = url.host_str().unwrap_or("").to_ascii_lowercase();
    url.set_host(Some(&lower_host))
        .map_err(|e| PairUriError::InvalidRelay(format!("set_host: {e}")))?;

    // Strip default ports.
    let default_port = match url.scheme() {
        "http" => Some(80u16),
        "https" => Some(443u16),
        _ => None,
    };
    if let Some(dp) = default_port {
        if url.port() == Some(dp) {
            url.set_port(None)
                .map_err(|()| PairUriError::InvalidRelay("set_port failed".into()))?;
        }
    }

    let mut s = url.to_string();
    // Strip a trailing `/` only when the path is empty (just the slash).
    if s.ends_with('/') && url.path() == "/" {
        s.pop();
    }
    Ok(s)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const AGENT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const RELAY_A: &str = "https://relay-a.example.com";
    const RELAY_B: &str = "https://relay-b.example.com";
    const RELAY_C: &str = "https://relay-c.example.com";
    const RELAY_D: &str = "https://relay-d.example.com";

    fn relays(v: &[&str]) -> Vec<String> {
        v.iter().map(std::string::ToString::to_string).collect()
    }

    // ── emit → parse round-trips ──────────────────────────────────────────

    #[test]
    fn round_trip_one_relay() {
        let uri = emit_pair_uri(AGENT, &relays(&[RELAY_A])).unwrap();
        let parsed = parse_pair_uri(&uri).unwrap();
        assert_eq!(parsed.agent_id_hex, AGENT);
        assert_eq!(parsed.relays, relays(&[RELAY_A]));
    }

    #[test]
    fn round_trip_four_relays() {
        let uri = emit_pair_uri(AGENT, &relays(&[RELAY_A, RELAY_B, RELAY_C, RELAY_D])).unwrap();
        let parsed = parse_pair_uri(&uri).unwrap();
        assert_eq!(parsed.agent_id_hex, AGENT);
        assert_eq!(parsed.relays, relays(&[RELAY_A, RELAY_B, RELAY_C, RELAY_D]));
    }

    // ── agent-id validation ───────────────────────────────────────────────

    #[test]
    fn reject_uppercase_agent_id() {
        let upper = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
        assert_eq!(
            emit_pair_uri(upper, &relays(&[RELAY_A])),
            Err(PairUriError::InvalidAgentId)
        );
    }

    #[test]
    fn reject_short_agent_id() {
        assert_eq!(
            emit_pair_uri("abc", &relays(&[RELAY_A])),
            Err(PairUriError::InvalidAgentId)
        );
    }

    #[test]
    fn reject_long_agent_id() {
        let long = "a".repeat(65);
        assert_eq!(
            emit_pair_uri(&long, &relays(&[RELAY_A])),
            Err(PairUriError::InvalidAgentId)
        );
    }

    // ── relay count validation ────────────────────────────────────────────

    #[test]
    fn reject_zero_relays() {
        assert_eq!(emit_pair_uri(AGENT, &[]), Err(PairUriError::NoRelays));
    }

    #[test]
    fn reject_five_relays() {
        assert_eq!(
            emit_pair_uri(
                AGENT,
                &relays(&[
                    RELAY_A,
                    RELAY_B,
                    RELAY_C,
                    RELAY_D,
                    "https://relay-e.example.com"
                ])
            ),
            Err(PairUriError::TooManyRelays)
        );
    }

    // ── relay URL validation ──────────────────────────────────────────────

    #[test]
    fn reject_file_scheme() {
        assert!(matches!(
            emit_pair_uri(AGENT, &relays(&["file:///etc/passwd"])),
            Err(PairUriError::InvalidRelay(_))
        ));
    }

    #[test]
    fn reject_ws_scheme() {
        assert!(matches!(
            emit_pair_uri(AGENT, &relays(&["ws://relay.example.com"])),
            Err(PairUriError::InvalidRelay(_))
        ));
    }

    #[test]
    fn reject_missing_host() {
        assert!(matches!(
            emit_pair_uri(AGENT, &relays(&["https://"])),
            Err(PairUriError::InvalidRelay(_))
        ));
    }

    #[test]
    fn reject_userinfo() {
        assert!(matches!(
            emit_pair_uri(AGENT, &relays(&["https://u:p@relay.example.com"])),
            Err(PairUriError::InvalidRelay(_))
        ));
    }

    #[test]
    fn reject_relay_exceeding_256_bytes() {
        // https:// (8) + 246 a's + .io (3) = 257 bytes
        let long = format!("https://{}.io", "a".repeat(246));
        assert_eq!(long.len(), 257);
        assert!(matches!(
            emit_pair_uri(AGENT, &relays(&[&long])),
            Err(PairUriError::InvalidRelay(_))
        ));
    }

    // ── total URI length cap ──────────────────────────────────────────────

    #[test]
    fn reject_uri_exceeding_512_bytes_on_parse() {
        // Two 255-byte relay URLs percent-encode to ~261 bytes each; together
        // they push the URI well past 512. Build the URI by hand (bypassing
        // emit so the length check happens only in parse).
        let relay = format!("https://{}.io", "a".repeat(244)); // 255 bytes, valid
        assert_eq!(relay.len(), 255);
        // Manually percent-encode : and / to match what url::Url would produce.
        let enc = relay.replace("https://", "https%3A%2F%2F");
        let uri = format!("x0x://pair/{AGENT}?r={enc}&r={enc}");
        assert!(
            uri.len() > MAX_URI_LEN,
            "test setup: uri must be >{MAX_URI_LEN} bytes, got {}",
            uri.len()
        );
        assert_eq!(parse_pair_uri(&uri), Err(PairUriError::TooLong));
    }

    // ── normalization and dedup ───────────────────────────────────────────

    #[test]
    fn normalize_uppercase_host_and_default_port_collapse_to_same() {
        // These three forms should all normalize to "https://r.io" and
        // dedupe to a single entry.
        let uri = emit_pair_uri(
            AGENT,
            &relays(&[
                "https://R.IO:443/",
                "https://r.io:443",
                "https://r.io/",
                "https://r.io",
            ]),
        )
        .unwrap();
        // After normalization+dedup only 1 entry survives — but emit
        // receives the raw list so parse must see 1.
        let parsed = parse_pair_uri(&uri).unwrap();
        assert_eq!(
            parsed.relays,
            vec!["https://r.io".to_string()],
            "all four forms must normalize+dedup to one: {:?}",
            parsed.relays
        );
    }

    #[test]
    fn dedup_preserves_first_seen_order() {
        // RELAY_A, RELAY_B, RELAY_A — after dedup: [RELAY_A, RELAY_B].
        let uri = emit_pair_uri(AGENT, &relays(&[RELAY_A, RELAY_B, RELAY_A])).unwrap();
        let parsed = parse_pair_uri(&uri).unwrap();
        assert_eq!(parsed.relays, relays(&[RELAY_A, RELAY_B]));
    }

    #[test]
    fn http_default_port_80_stripped() {
        let with_port = "http://relay.example.com:80/path";
        let without_port = "http://relay.example.com/path";
        let n1 = normalize_relay(with_port).unwrap();
        let n2 = normalize_relay(without_port).unwrap();
        assert_eq!(n1, n2);
    }

    // ── parse-only rejection paths ────────────────────────────────────────

    #[test]
    fn parse_rejects_wrong_scheme() {
        let uri = format!("http://pair/{AGENT}?r={RELAY_A}");
        assert_eq!(parse_pair_uri(&uri), Err(PairUriError::InvalidAgentId));
    }

    #[test]
    fn parse_rejects_wrong_host_segment() {
        let uri = format!("x0x://agent/{AGENT}?r={RELAY_A}");
        assert_eq!(parse_pair_uri(&uri), Err(PairUriError::InvalidAgentId));
    }

    #[test]
    fn parse_rejects_five_r_params() {
        let uri = format!(
            "x0x://pair/{AGENT}?r={RELAY_A}&r={RELAY_B}&r={RELAY_C}&r={RELAY_D}&r={RELAY_A}"
        );
        assert_eq!(parse_pair_uri(&uri), Err(PairUriError::TooManyRelays));
    }

    #[test]
    fn parse_rejects_no_r_params() {
        let uri = format!("x0x://pair/{AGENT}");
        assert_eq!(parse_pair_uri(&uri), Err(PairUriError::NoRelays));
    }

    // ── adversarial edge-case pins ────────────────────────────────────────

    #[test]
    fn parse_empty_r_value_errors_invalid_relay() {
        // `?r=` with no value: the empty string fails URL parse ("relative
        // URL without a base"), surfacing as InvalidRelay rather than a
        // silent empty-relay accept.
        let uri = format!("x0x://pair/{AGENT}?r=");
        assert!(matches!(
            parse_pair_uri(&uri),
            Err(PairUriError::InvalidRelay(_))
        ));
    }

    #[test]
    fn parse_percent_encoded_null_in_host_is_rejected() {
        // A `%00` decoded into the host portion makes the relay an invalid
        // IDNA host, so validate_relay's re-parse rejects it.
        let uri = format!("x0x://pair/{AGENT}?r=https://re%00lay.io/");
        assert!(matches!(
            parse_pair_uri(&uri),
            Err(PairUriError::InvalidRelay(_))
        ));
    }

    #[test]
    fn parse_trailing_control_chars_are_stripped_not_rejected() {
        // FINDING: trailing `%0A%00` after the path do NOT reject — the url
        // crate strips trailing control characters on re-parse, so the relay
        // normalizes to the clean host. Pinned to document the actual
        // (lenient) behavior, not the assumed rejection.
        let uri = format!("x0x://pair/{AGENT}?r=https://relay.io/%0A%00");
        let parsed =
            parse_pair_uri(&uri).expect("trailing control chars are stripped, not rejected");
        assert_eq!(parsed.relays, vec!["https://relay.io".to_string()]);
    }

    #[test]
    fn parse_uppercase_scheme_is_accepted_url_crate_lowercases() {
        // The url crate lowercases the scheme on parse, so `X0X://` matches
        // the `x0x` scheme check and the URI is accepted.
        let uri = format!("X0X://pair/{AGENT}?r={RELAY_A}");
        let parsed = parse_pair_uri(&uri).expect("uppercase scheme lowercased by url crate");
        assert_eq!(parsed.agent_id_hex, AGENT);
        assert_eq!(parsed.relays, relays(&[RELAY_A]));
    }

    #[test]
    fn parse_rejects_63_char_agent_id() {
        let short = "a".repeat(63);
        let uri = format!("x0x://pair/{short}?r={RELAY_A}");
        assert_eq!(parse_pair_uri(&uri), Err(PairUriError::InvalidAgentId));
    }

    #[test]
    fn parse_rejects_65_char_agent_id() {
        let long = "a".repeat(65);
        let uri = format!("x0x://pair/{long}?r={RELAY_A}");
        assert_eq!(parse_pair_uri(&uri), Err(PairUriError::InvalidAgentId));
    }

    #[test]
    fn parse_rejects_64_char_id_with_non_hex_char() {
        // 'g' is not a hex digit; a 64-char id that is otherwise hex must
        // still be rejected.
        let bad = format!("g{}", "0".repeat(63));
        assert_eq!(bad.len(), 64);
        let uri = format!("x0x://pair/{bad}?r={RELAY_A}");
        assert_eq!(parse_pair_uri(&uri), Err(PairUriError::InvalidAgentId));
    }

    #[test]
    fn parse_boundary_512_bytes_ok_513_too_long() {
        // The total-length gate runs before any relay validation. Build two
        // distinct valid relays whose values pad the URI to an exact byte
        // count: 512 parses, 513 errors TooLong.
        fn uri_of_len(total: usize) -> String {
            // fixed bytes: "x0x://pair/" (11) + AGENT (64) + "?r=" (3)
            // + "&r=" (3) = 81; two relays at 11 bytes overhead each.
            let pad_budget = total - 81 - 22;
            let pad1 = pad_budget / 2;
            let pad2 = pad_budget - pad1;
            let r1 = format!("https://{}.io", "a".repeat(pad1));
            let r2 = format!("https://{}.io", "b".repeat(pad2));
            format!("x0x://pair/{AGENT}?r={r1}&r={r2}")
        }

        let ok = uri_of_len(512);
        assert_eq!(ok.len(), 512, "test setup: must be exactly 512 bytes");
        assert!(
            parse_pair_uri(&ok).is_ok(),
            "a 512-byte URI must parse: {:?}",
            parse_pair_uri(&ok)
        );

        let too_long = uri_of_len(513);
        assert_eq!(too_long.len(), 513, "test setup: must be exactly 513 bytes");
        assert_eq!(parse_pair_uri(&too_long), Err(PairUriError::TooLong));
    }

    #[test]
    fn parse_rejects_multi_segment_path() {
        // `x0x://pair/<64-hex>/extra` puts "<64-hex>/extra" in the path; that
        // is not 64-hex, so the agent-id check rejects it (no mangling).
        let uri = format!("x0x://pair/{AGENT}/extra?r={RELAY_A}");
        assert_eq!(parse_pair_uri(&uri), Err(PairUriError::InvalidAgentId));
    }

    #[test]
    fn parse_relay_fragment_is_preserved_through_normalization() {
        // A relay URL carrying a percent-encoded `#fragment` keeps it: the
        // fragment is part of the relay value, normalization neither strips
        // nor rejects it (the trailing-slash strip only fires on an empty
        // path, which a fragment-bearing url::to_string never ends in).
        let uri = format!("x0x://pair/{AGENT}?r=https://relay.io/%23frag");
        let parsed = parse_pair_uri(&uri).expect("fragment-bearing relay parses");
        assert_eq!(parsed.relays, vec!["https://relay.io/#frag".to_string()]);
    }
}

// ── integration tests (wiremock) ──────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod import_tests {
    use super::*;
    use crate::messages::StoredContactCard;
    use fetchit_relay_proto::pair_record::{pair_signing_input, PairRecordV1};
    use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};
    use tempfile::tempdir;

    // Build a valid PairRecordV1 signed by a fresh ML-DSA-65 keypair.
    fn mk_pair_record(relays: &[&str]) -> (PairRecordV1, Vec<u8>) {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;

        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let pk_bytes = pk.to_bytes();
        let agent_id_hex = hex::encode(fetchit_relay_proto::derive_agent_id(&pk_bytes));
        let relay_strs: Vec<String> = relays
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        let kem_pk = vec![0u8; 1184];

        let input =
            pair_signing_input(&agent_id_hex, &pk_bytes, &kem_pk, &relay_strs, 1_000).unwrap();
        let sig = dsa.sign(&sk, &input).unwrap().to_bytes();

        let record = PairRecordV1 {
            agent_id_hex,
            ml_dsa_pubkey_b64: B64.encode(&pk_bytes),
            kem_pubkey_b64: B64.encode(&kem_pk),
            advertised_relays: relay_strs,
            issued_at_ms: 1_000,
            sig_b64: B64.encode(sig),
        };
        (record, pk_bytes)
    }

    fn make_layout(dir: &std::path::Path) -> crate::local_store::StoreLayout {
        crate::local_store::StoreLayout::ensure(dir.to_path_buf()).unwrap()
    }

    /// Build a `StoredContactCard` from a `PairRecordV1` the same way
    /// `Client::import_pair_uri` does.
    fn pair_record_to_stored_contact(record: &PairRecordV1) -> StoredContactCard {
        StoredContactCard {
            agent_id_hex: record.agent_id_hex.clone(),
            display_name: String::new(),
            kem_public_key_b64: record.kem_pubkey_b64.clone(),
            agent_public_key_b64: Some(record.ml_dsa_pubkey_b64.clone()),
            rendezvous_hints: None,
            last_hint_epoch_ms: None,
        }
    }

    #[tokio::test]
    async fn import_happy_path_contact_saved() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let relay_url = format!("{}/", server.uri());
        let (record, _pk) = mk_pair_record(&[&relay_url]);

        Mock::given(method("GET"))
            .and(path(format!("/v1/pair-record/{}", record.agent_id_hex)))
            .respond_with(ResponseTemplate::new(200).set_body_json(&record))
            .mount(&server)
            .await;

        let dir = tempdir().unwrap();
        let layout = make_layout(dir.path());

        let relays = vec![relay_url.clone()];
        let uri = emit_pair_uri(&record.agent_id_hex, &relays).unwrap();
        let parsed = parse_pair_uri(&uri).unwrap();

        let http = reqwest::Client::new();
        let mut last_err = String::new();
        let mut fetched = None;
        for relay_str in &parsed.relays {
            let relay = url::Url::parse(relay_str).unwrap();
            match crate::pair::fetch_pair_record_by_id(&relay, &parsed.agent_id_hex, &http).await {
                Ok(r) => {
                    fetched = Some(r);
                    break;
                }
                Err(e) => last_err = e.to_string(),
            }
        }
        let fetched = fetched.unwrap_or_else(|| {
            panic!("all relays failed: {last_err}");
        });

        let stored = pair_record_to_stored_contact(&fetched);
        stored.save(&layout).unwrap();

        let loaded = StoredContactCard::load(&layout, &record.agent_id_hex)
            .unwrap()
            .expect("contact must be saved");
        assert_eq!(loaded.agent_id_hex, record.agent_id_hex);
        assert_eq!(loaded.kem_public_key_b64, record.kem_pubkey_b64);
    }

    #[tokio::test]
    async fn import_all_relays_fail_returns_err() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let relay_url = format!("{}/", server.uri());
        let agent_id = "a".repeat(64);
        let relays = vec![relay_url];
        let uri = emit_pair_uri(&agent_id, &relays).unwrap();
        let parsed = parse_pair_uri(&uri).unwrap();

        let http = reqwest::Client::new();
        let mut any_ok = false;
        for relay_str in &parsed.relays {
            let relay = url::Url::parse(relay_str).unwrap();
            if crate::pair::fetch_pair_record_by_id(&relay, &parsed.agent_id_hex, &http)
                .await
                .is_ok()
            {
                any_ok = true;
            }
        }
        assert!(!any_ok, "expected all relays to fail");
    }
}
