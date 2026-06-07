//! Per-instance HTTP Signature format preference cache + dispatcher.
//!
//! Stage 2.1b runtime glue between the RFC 9421 signer
//! ([`crate::signature`]) and the draft-cavage signer
//! ([`crate::signature_cavage`]). Two responsibilities:
//!
//! 1. Remember, per inbox-instance origin (`scheme://host[:port]`),
//!    which signature wire format the peer prefers, with a **24-hour
//!    TTL**. Observations are recorded by Stage 3 (inbox response
//!    inspection + `Accept-Signature` parsing) and read by the
//!    delivery path.
//! 2. Dispatch a signing call to the right signer based on cache
//!    lookup, falling back to a caller-supplied default when the
//!    cache is cold or stale.
//!
//! The cache framing is "does this peer **prefer** 9421" — not "do we
//! have to fall back to cavage". RFC 9421's `@target-uri` covered
//! component is reconstructed by the receiver from `X-Forwarded-*`
//! headers; on proxied inboxes (every Cloudflare-fronted Mastodon,
//! every k8s ingress) it silently mismatches and the signature fails.
//! cavage's `(request-target)` is just the relative URL the receiver
//! sees on the wire, so it survives that topology. The pragmatic
//! default is therefore [`SignatureFormat::Cavage`]; we upgrade to
//! [`SignatureFormat::Rfc9421`] only when the peer signals support.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use crate::signature::{HttpSignatureError, HttpSignatureKey, SignedHeaders};
use crate::signature_cavage::CavageSignedHeaders;

/// 24h cache TTL for an observed preference. After this window the
/// peer might have changed its negotiation behaviour; force a fresh
/// observation.
pub const CAPABILITY_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Which HTTP Signature wire format a peer prefers / we should emit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureFormat {
    /// draft-cavage-12 — single `Signature` header,
    /// `(request-target) host date digest`, `Digest: SHA-256=...`.
    /// The conservative default for outbound deliveries to unknown
    /// peers because it survives proxied-inbox topologies that
    /// rewrite `@target-uri`.
    Cavage,
    /// RFC 9421 — `Signature-Input` + `Signature` headers,
    /// `("@method" "@target-uri" "host" "date" "content-digest")`,
    /// `Content-Digest: sha-256=:...:` (RFC 9530 structured-fields).
    /// Use when the peer has signalled support — e.g. via
    /// `Accept-Signature: sig1=...` on a prior inbox response.
    Rfc9421,
}

/// Signed headers produced by either wire format. Callers assemble
/// their HTTP request from [`Self::into_request_headers`] without
/// needing to know which format was used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutboundSignedHeaders {
    /// RFC 9421 wire shape.
    Rfc9421(SignedHeaders),
    /// draft-cavage wire shape.
    Cavage(CavageSignedHeaders),
}

impl OutboundSignedHeaders {
    /// Which wire format produced these headers.
    #[must_use]
    pub fn format(&self) -> SignatureFormat {
        match self {
            Self::Rfc9421(_) => SignatureFormat::Rfc9421,
            Self::Cavage(_) => SignatureFormat::Cavage,
        }
    }

    /// Flatten the signed headers into HTTP `(name, value)` pairs to
    /// attach to the outbound POST. RFC 9421 emits four (`Date`,
    /// `Content-Digest`, `Signature-Input`, `Signature`); cavage
    /// emits three (`Date`, `Digest`, `Signature`).
    #[must_use]
    pub fn into_request_headers(self) -> Vec<(&'static str, String)> {
        match self {
            Self::Rfc9421(s) => vec![
                ("Date", s.date),
                ("Content-Digest", s.content_digest),
                ("Signature-Input", s.signature_input),
                ("Signature", s.signature),
            ],
            Self::Cavage(s) => vec![
                ("Date", s.date),
                ("Digest", s.digest),
                ("Signature", s.signature),
            ],
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct CapabilityEntry {
    format: SignatureFormat,
    observed_at: SystemTime,
}

/// In-process cache of per-instance signature-format preferences with
/// a 24-hour TTL.
///
/// Keys are inbox **origins** (`scheme://host[:non-default-port]`) so
/// every actor inbox on a given Mastodon instance shares one
/// preference. Stage 3 inbox-response inspection writes observations
/// via [`Self::observe`]; the delivery path reads via
/// [`Self::preference`].
///
/// `SystemTime` is injected on every call rather than read internally
/// so unit tests are deterministic and the cache stays a pure data
/// structure.
#[derive(Debug, Default)]
pub struct SignatureCapabilityCache {
    inner: Mutex<HashMap<String, CapabilityEntry>>,
}

impl SignatureCapabilityCache {
    /// Empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Cached preference for `origin` if still within the 24h TTL,
    /// `None` otherwise (cache cold or entry stale).
    ///
    /// `now` is the timestamp to evaluate freshness against —
    /// production callers pass `SystemTime::now()`, tests pass a
    /// fixed `SystemTime` for determinism.
    #[must_use]
    pub fn preference(&self, origin: &str, now: SystemTime) -> Option<SignatureFormat> {
        let guard = self.inner.lock().ok()?;
        let entry = guard.get(origin)?;
        match now.duration_since(entry.observed_at) {
            Ok(age) if age < CAPABILITY_CACHE_TTL => Some(entry.format),
            _ => None,
        }
    }

    /// Record that `origin` prefers `format`. Resets the 24h TTL.
    ///
    /// Idempotent: re-observing the same `(origin, format)` just
    /// refreshes the timestamp; observing a different format
    /// replaces the previous entry.
    pub fn observe(&self, origin: String, format: SignatureFormat, now: SystemTime) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.insert(
                origin,
                CapabilityEntry {
                    format,
                    observed_at: now,
                },
            );
        }
    }

    /// Drop every entry older than the 24h TTL. Optional — the
    /// `preference` lookup already filters by age — but useful for
    /// long-running services that want bounded memory.
    pub fn sweep(&self, now: SystemTime) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.retain(|_, entry| {
                matches!(
                    now.duration_since(entry.observed_at),
                    Ok(age) if age < CAPABILITY_CACHE_TTL
                )
            });
        }
    }

    /// Live entry count. Test-helper-shaped but useful for ops
    /// metrics too.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().map_or(0, |g| g.len())
    }

    /// `true` when the cache holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Extract an inbox-instance origin string from a delivery URL.
///
/// Returns `"<scheme>://<host>[:<port>]"` with port suffix only when
/// `url::Url::port()` is `Some` (i.e. non-default for the scheme).
/// Returns `None` when the URL has no host component.
///
/// All actor inboxes on a given Mastodon instance share one origin,
/// so the cache key collapses to one entry per instance even when an
/// instance hosts many actors.
#[must_use]
pub fn inbox_origin(url: &url::Url) -> Option<String> {
    let host = url.host_str()?;
    let origin = match url.port() {
        Some(port) => format!("{scheme}://{host}:{port}", scheme = url.scheme()),
        None => format!("{scheme}://{host}", scheme = url.scheme()),
    };
    Some(origin)
}

/// Sign an outbound POST, picking RFC 9421 or draft-cavage based on
/// the per-instance preference cache.
///
/// Resolution order:
/// 1. Look up the inbox-instance origin in `cache`.
/// 2. If still within the 24h TTL, use the cached preference.
/// 3. Otherwise use `default` — the caller's pragmatic baseline. We
///    recommend [`SignatureFormat::Cavage`] for unknown instances.
///
/// `now` is used both for cache freshness and to derive the RFC 9421
/// `created` parameter (Unix seconds), so production callers should
/// derive `date_header` and `now` from the same `SystemTime`.
///
/// # Errors
/// Propagates any [`HttpSignatureError`] from the chosen signer.
pub fn sign_post_with_preference(
    key: &HttpSignatureKey,
    url: &url::Url,
    body: &[u8],
    date_header: &str,
    now: SystemTime,
    cache: &SignatureCapabilityCache,
    default: SignatureFormat,
) -> Result<OutboundSignedHeaders, HttpSignatureError> {
    let format = inbox_origin(url)
        .and_then(|origin| cache.preference(&origin, now))
        .unwrap_or(default);

    match format {
        SignatureFormat::Rfc9421 => {
            let created = i64::try_from(
                now.duration_since(SystemTime::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()),
            )
            .unwrap_or(i64::MAX);
            let signed = key.sign_post_rfc9421(url, body, date_header, created)?;
            Ok(OutboundSignedHeaders::Rfc9421(signed))
        }
        SignatureFormat::Cavage => {
            let signed = key.sign_post_cavage(url, body, date_header)?;
            Ok(OutboundSignedHeaders::Cavage(signed))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use rsa::rand_core::OsRng;
    use rsa::RsaPrivateKey;
    use sha2::Sha256;
    use std::sync::OnceLock;

    fn test_key() -> &'static HttpSignatureKey {
        static KEY: OnceLock<HttpSignatureKey> = OnceLock::new();
        KEY.get_or_init(|| {
            let priv_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
            // Touch SigningKey<Sha256> to ensure the same trait bound
            // path the production code uses compiles in this test.
            let _ = SigningKey::<Sha256>::new(priv_key.clone());
            let priv_pem = priv_key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
            HttpSignatureKey {
                key_id: "https://etchit.io/actors/josh#main-key".into(),
                rsa_private_pem: priv_pem,
            }
        })
    }

    fn t0() -> SystemTime {
        // 2026-06-07T15:00:00Z — fixed anchor for deterministic tests.
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_780_412_400)
    }

    #[test]
    fn inbox_origin_default_port_omits_suffix() {
        let url: url::Url = "https://example.com/users/alice/inbox".parse().unwrap();
        assert_eq!(inbox_origin(&url).as_deref(), Some("https://example.com"));
    }

    #[test]
    fn inbox_origin_non_default_port_includes_suffix() {
        let url: url::Url = "https://example.com:8443/inbox".parse().unwrap();
        assert_eq!(
            inbox_origin(&url).as_deref(),
            Some("https://example.com:8443")
        );
    }

    #[test]
    fn inbox_origin_http_scheme_preserved() {
        // Plain http unrealistic in production but useful for local
        // testing. Scheme must round-trip.
        let url: url::Url = "http://localhost:8080/inbox".parse().unwrap();
        assert_eq!(inbox_origin(&url).as_deref(), Some("http://localhost:8080"));
    }

    #[test]
    fn inbox_origin_missing_host_returns_none() {
        let url: url::Url = "file:///tmp/whatever".parse().unwrap();
        assert!(inbox_origin(&url).is_none());
    }

    #[test]
    fn inbox_origin_collapses_per_actor_paths_to_one_origin() {
        // All actor inboxes on a given Mastodon instance share one
        // origin, so the cache key is the same.
        let alice: url::Url = "https://mastodon.example/users/alice/inbox"
            .parse()
            .unwrap();
        let bob: url::Url = "https://mastodon.example/users/bob/inbox".parse().unwrap();
        assert_eq!(inbox_origin(&alice), inbox_origin(&bob));
    }

    #[test]
    fn cache_starts_empty() {
        let cache = SignatureCapabilityCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        assert!(cache.preference("https://mastodon.example", t0()).is_none());
    }

    #[test]
    fn cache_observe_then_read_within_ttl() {
        let cache = SignatureCapabilityCache::new();
        cache.observe(
            "https://mastodon.example".into(),
            SignatureFormat::Rfc9421,
            t0(),
        );
        // Fresh lookup at the same instant.
        assert_eq!(
            cache.preference("https://mastodon.example", t0()),
            Some(SignatureFormat::Rfc9421)
        );
        // Still fresh just under the TTL boundary.
        let almost_expired = t0() + CAPABILITY_CACHE_TTL - Duration::from_secs(1);
        assert_eq!(
            cache.preference("https://mastodon.example", almost_expired),
            Some(SignatureFormat::Rfc9421)
        );
    }

    #[test]
    fn cache_entry_expires_after_ttl() {
        let cache = SignatureCapabilityCache::new();
        cache.observe(
            "https://mastodon.example".into(),
            SignatureFormat::Rfc9421,
            t0(),
        );
        let expired = t0() + CAPABILITY_CACHE_TTL + Duration::from_secs(1);
        assert!(cache
            .preference("https://mastodon.example", expired)
            .is_none());
    }

    #[test]
    fn cache_observe_replaces_previous_format() {
        let cache = SignatureCapabilityCache::new();
        cache.observe(
            "https://mastodon.example".into(),
            SignatureFormat::Rfc9421,
            t0(),
        );
        cache.observe(
            "https://mastodon.example".into(),
            SignatureFormat::Cavage,
            t0() + Duration::from_secs(60),
        );
        assert_eq!(
            cache.preference("https://mastodon.example", t0() + Duration::from_secs(120)),
            Some(SignatureFormat::Cavage)
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cache_re_observe_refreshes_ttl() {
        let cache = SignatureCapabilityCache::new();
        cache.observe(
            "https://mastodon.example".into(),
            SignatureFormat::Rfc9421,
            t0(),
        );
        // Re-observe just before original TTL would expire.
        let refresh = t0() + CAPABILITY_CACHE_TTL - Duration::from_secs(60);
        cache.observe(
            "https://mastodon.example".into(),
            SignatureFormat::Rfc9421,
            refresh,
        );
        // Original TTL window has now passed, but the refresh kept
        // the entry alive.
        let past_original_ttl = t0() + CAPABILITY_CACHE_TTL + Duration::from_secs(10);
        assert_eq!(
            cache.preference("https://mastodon.example", past_original_ttl),
            Some(SignatureFormat::Rfc9421)
        );
    }

    #[test]
    fn cache_sweep_drops_stale_entries() {
        let cache = SignatureCapabilityCache::new();
        cache.observe(
            "https://fresh.example".into(),
            SignatureFormat::Rfc9421,
            t0() + CAPABILITY_CACHE_TTL,
        );
        cache.observe(
            "https://stale.example".into(),
            SignatureFormat::Cavage,
            t0(),
        );
        assert_eq!(cache.len(), 2);

        let sweep_at = t0() + CAPABILITY_CACHE_TTL + Duration::from_secs(1);
        cache.sweep(sweep_at);
        assert_eq!(cache.len(), 1);
        assert!(cache
            .preference("https://stale.example", sweep_at)
            .is_none());
        assert_eq!(
            cache.preference("https://fresh.example", sweep_at),
            Some(SignatureFormat::Rfc9421)
        );
    }

    #[test]
    fn dispatcher_falls_back_to_default_when_cache_cold() {
        let key = test_key();
        let cache = SignatureCapabilityCache::new();
        let url: url::Url = "https://unknown.example/inbox".parse().unwrap();

        let signed = sign_post_with_preference(
            key,
            &url,
            b"body",
            "Sun, 06 Nov 1994 08:49:37 GMT",
            t0(),
            &cache,
            SignatureFormat::Cavage,
        )
        .unwrap();
        assert_eq!(signed.format(), SignatureFormat::Cavage);
    }

    #[test]
    fn dispatcher_uses_cached_preference_over_default() {
        let key = test_key();
        let cache = SignatureCapabilityCache::new();
        cache.observe(
            "https://known.example".into(),
            SignatureFormat::Rfc9421,
            t0(),
        );
        let url: url::Url = "https://known.example/inbox".parse().unwrap();

        let signed = sign_post_with_preference(
            key,
            &url,
            b"body",
            "Sun, 06 Nov 1994 08:49:37 GMT",
            t0(),
            &cache,
            // Default would say Cavage, but the cache prefers 9421.
            SignatureFormat::Cavage,
        )
        .unwrap();
        assert_eq!(signed.format(), SignatureFormat::Rfc9421);
    }

    #[test]
    fn dispatcher_falls_back_when_cached_entry_expired() {
        let key = test_key();
        let cache = SignatureCapabilityCache::new();
        cache.observe(
            "https://expired.example".into(),
            SignatureFormat::Rfc9421,
            t0(),
        );
        let url: url::Url = "https://expired.example/inbox".parse().unwrap();
        let way_later = t0() + CAPABILITY_CACHE_TTL + Duration::from_secs(60);

        let signed = sign_post_with_preference(
            key,
            &url,
            b"body",
            "Sun, 06 Nov 1994 08:49:37 GMT",
            way_later,
            &cache,
            SignatureFormat::Cavage,
        )
        .unwrap();
        assert_eq!(signed.format(), SignatureFormat::Cavage);
    }

    #[test]
    fn into_request_headers_rfc9421_emits_four_headers() {
        let signed = SignedHeaders {
            date: "Sun, 06 Nov 1994 08:49:37 GMT".into(),
            content_digest: "sha-256=:AAAA:".into(),
            signature_input: "sig1=(...)".into(),
            signature: "sig1=:BBBB:".into(),
        };
        let headers = OutboundSignedHeaders::Rfc9421(signed).into_request_headers();
        let names: Vec<&str> = headers.iter().map(|(n, _)| *n).collect();
        assert_eq!(
            names,
            vec!["Date", "Content-Digest", "Signature-Input", "Signature"]
        );
    }

    #[test]
    fn into_request_headers_cavage_emits_three_headers() {
        let signed = CavageSignedHeaders {
            date: "Sun, 06 Nov 1994 08:49:37 GMT".into(),
            digest: "SHA-256=AAAA".into(),
            signature: r#"keyId="X",algorithm="rsa-sha256",headers="(request-target) host date digest",signature="BBBB""#
                .into(),
        };
        let headers = OutboundSignedHeaders::Cavage(signed).into_request_headers();
        let names: Vec<&str> = headers.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, vec!["Date", "Digest", "Signature"]);
    }
}
