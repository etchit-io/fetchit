//! `FediverseTransport` — outbound HTTPS POST delivery for
//! `ActivityPub` activities.
//!
//! Stage 2.2 of the M4 stack. Composes the Stage 2.1 signers
//! ([`crate::signature_cache::sign_post_with_preference_keyed`]) with
//! a `reqwest` client + retry policy + per-actor signing-key cache.
//!
//! ## Boundary
//!
//! Per plan decision `[C]`, [`FediverseTransport::deliver`] takes a
//! `&[u8] body` for Stage 2.2 (`PublicPost` lands Stage 5; the chat
//! layer will provide a wrapper that serializes a `&PublicPost` to
//! the `Create{Note}` JSON-LD bytes this function takes).
//! `FediverseTransport` is **not** a `fetchit_chat::Transport` and
//! never sees an `Envelope` — DMs cannot cross the bridge at the
//! type-system layer.
//!
//! ## Trust boundary
//!
//! Per Alice's I1 in the 2.1b cross-review: the underlying RSA
//! signers do not verify that the destination URL matches the
//! signing actor. A misconfigured (or maliciously-fed) destination
//! URL of `https://attacker.example/inbox` would otherwise be happily
//! signed with `keyId=https://etchit.io/actors/josh#main-key`, and
//! the receiver would attribute the POST to us. [`validate_delivery_url`]
//! is the deliberate trust gate that runs **before** signing.
//!
//! At Stage 2.2 the gate is structural only: the destination must
//! have a host and use `https` (or `http` for local-dev / tests).
//! Stage 4 adds the real trust-list / `EntryKind::ActorUrl` denylist
//! consultation + the follower-collection match. Callers are
//! expected to have already validated recipients against their own
//! follower-collection before invoking `deliver`.
//!
//! ## Retry policy
//!
//! - **2xx**: success.
//! - **401**: try the opposite signature format once. If that also
//!   401s, return [`DeliveryError::BothFormatsRejected`]. If the flip
//!   SUCCEEDS, the working format is written back to the capability
//!   cache (#174 failure-aware correction) so the next delivery to
//!   that instance skips the wasted 401 + flip for the 24h TTL.
//!   Affirmative "prefers" signals from inbox-response inspection
//!   remain a separate Stage 3 `cache.observe(...)` path.
//! - **Other 4xx**: no retry — semantic failure, surface the status.
//! - **5xx / network / timeout**: retry up to
//!   [`MAX_DELIVERY_ATTEMPTS`] with 1s/2s/4s backoff.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;
use sha2::Sha256;
use thiserror::Error;

use crate::signature::{HttpSignatureError, HttpSignatureKey};
use crate::signature_cache::{
    inbox_origin, sign_post_with_format_keyed, sign_post_with_preference_keyed,
    OutboundSignedHeaders, SignatureCapabilityCache, SignatureFormat,
};

/// `Content-Type` value attached to every outbound activity POST.
pub const ACTIVITY_JSON_CONTENT_TYPE: &str = "application/activity+json";

/// Maximum retry attempts for transient failures (5xx / network /
/// timeout). 401 retries are separate and limited to one
/// flip-and-retry.
pub const MAX_DELIVERY_ATTEMPTS: u32 = 3;

/// Initial backoff between retry attempts. Doubles on each retry,
/// so a full 3-attempt run waits 1s + 2s = 3s before giving up.
pub const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// Errors a `FediverseTransport::deliver` call can return.
#[derive(Debug, Error)]
pub enum DeliveryError {
    /// The destination URL failed the structural gate (no host,
    /// non-http(s) scheme, etc.).
    #[error("delivery URL refused: {0}")]
    InvalidDeliveryUrl(String),
    /// The HTTP Signature signer failed (invalid PEM, missing host
    /// on URL, RSA op failure).
    #[error("signature construction failed: {0}")]
    Signature(#[from] HttpSignatureError),
    /// `reqwest` returned a transport-level error.
    #[error("HTTP transport error: {0}")]
    Http(String),
    /// The receiver returned a non-401 4xx — semantic failure, no
    /// retry.
    #[error("receiver rejected POST with HTTP {status} (client error)")]
    ClientError {
        /// HTTP status code returned by the receiver.
        status: u16,
    },
    /// The receiver returned 5xx on every retry attempt.
    #[error("receiver returned HTTP {status} after {attempts} attempts")]
    ServerError {
        /// HTTP status code on the final attempt.
        status: u16,
        /// Total attempts made (including the first).
        attempts: u32,
    },
    /// Both signature formats were rejected with 401. Likely a real
    /// authentication failure (mismatched key, expired key,
    /// blocked-by-policy) rather than a format-negotiation issue.
    #[error("receiver rejected both signature formats with 401")]
    BothFormatsRejected,
}

/// Outcome of a successful delivery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryReport {
    /// Which wire format the receiver ultimately accepted.
    pub format_used: SignatureFormat,
    /// HTTP status code returned (typically 200, 201, or 202).
    pub status: u16,
    /// Total attempts made (1 if first attempt succeeded; 2 if a
    /// 401 flip-and-retry succeeded on second attempt; 1..=N for
    /// 5xx-recovered).
    pub attempts: u32,
}

/// Per-actor signing-key cache.
///
/// Caches one `Arc<SigningKey<Sha256>>` per `HttpSignatureKey::key_id`
/// so the PKCS#8 decode runs once per actor, not once per delivery
/// (Alice's S2 carryover from the 2.1a review). Calls are
/// thread-safe via the inner `Mutex`.
#[derive(Default)]
struct SigningKeyCache {
    inner: Mutex<HashMap<String, Arc<SigningKey<Sha256>>>>,
}

impl SigningKeyCache {
    fn new() -> Self {
        Self::default()
    }

    /// Return the cached signing key for `key.key_id`, decoding the
    /// PEM on the first call.
    fn get_or_decode(
        &self,
        key: &HttpSignatureKey,
    ) -> Result<Arc<SigningKey<Sha256>>, HttpSignatureError> {
        if let Some(cached) = self
            .inner
            .lock()
            .ok()
            .and_then(|g| g.get(&key.key_id).cloned())
        {
            return Ok(cached);
        }
        let priv_key = RsaPrivateKey::from_pkcs8_pem(&key.rsa_private_pem)
            .map_err(|e| HttpSignatureError::InvalidPrivateKey(format!("{e}")))?;
        let signing_key = Arc::new(SigningKey::<Sha256>::new(priv_key));
        if let Ok(mut guard) = self.inner.lock() {
            guard.insert(key.key_id.clone(), signing_key.clone());
        }
        Ok(signing_key)
    }
}

/// Outbound HTTPS POST delivery for `ActivityPub` activities.
///
/// Owns a shared `reqwest::Client`, the per-instance
/// [`SignatureCapabilityCache`], and a per-actor signing-key cache.
/// Instantiate one per process and share across `deliver` callers.
pub struct FediverseTransport {
    http: reqwest::Client,
    capability_cache: Arc<SignatureCapabilityCache>,
    signing_key_cache: SigningKeyCache,
    default_format: SignatureFormat,
}

impl FediverseTransport {
    /// New transport with a default `reqwest::Client`, an empty
    /// capability cache, and `default_format` = [`SignatureFormat::Cavage`]
    /// for unknown peers (the conservative working path on proxied
    /// inboxes — see [`crate::signature_cavage`] for the rationale).
    ///
    /// # Errors
    /// Returns [`DeliveryError::Http`] if the default `reqwest::Client`
    /// builder fails (e.g. system has no usable TLS backend).
    pub fn new() -> Result<Self, DeliveryError> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("fetchit-fedi/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| DeliveryError::Http(format!("reqwest builder: {e}")))?;
        Ok(Self::with_client(
            http,
            Arc::new(SignatureCapabilityCache::new()),
            SignatureFormat::Cavage,
        ))
    }

    /// Construct from an explicit `reqwest::Client` + capability
    /// cache + default. Used by tests (custom timeouts, shared
    /// cache) and by production code that wants to share one
    /// `reqwest::Client` across modules.
    #[must_use]
    pub fn with_client(
        http: reqwest::Client,
        capability_cache: Arc<SignatureCapabilityCache>,
        default_format: SignatureFormat,
    ) -> Self {
        Self {
            http,
            capability_cache,
            signing_key_cache: SigningKeyCache::new(),
            default_format,
        }
    }

    /// Shared handle to the capability cache. Stage 3 inbox-response
    /// handler uses this to call `cache.observe(...)` on observed
    /// peer-prefers-format signals.
    #[must_use]
    pub fn capability_cache(&self) -> &Arc<SignatureCapabilityCache> {
        &self.capability_cache
    }

    /// Deliver `body` as an `application/activity+json` POST to
    /// `inbox_url`, signing with `key`'s identity.
    ///
    /// `actor_url` is the public URL of the signing actor (used by
    /// [`validate_delivery_url`] to gate cross-origin trust at the
    /// 2.2 baseline + reserved for Stage 4 trust-list integration).
    /// Both `inbox_url` and `actor_url` must have a host and use
    /// `http(s)` — Stage 4 will narrow this to `https`-only +
    /// trust-list filtering.
    ///
    /// # Errors
    /// Returns the appropriate [`DeliveryError`] variant. See struct
    /// docs for retry semantics.
    pub async fn deliver(
        &self,
        key: &HttpSignatureKey,
        body: &[u8],
        inbox_url: &url::Url,
        actor_url: &url::Url,
    ) -> Result<DeliveryReport, DeliveryError> {
        validate_delivery_url(inbox_url, actor_url).map_err(DeliveryError::InvalidDeliveryUrl)?;

        let signing_key = self.signing_key_cache.get_or_decode(key)?;
        let now = SystemTime::now();
        let date_header = format_imf_fixdate(now);

        // First attempt: use the cached preference (or default).
        let primary = sign_post_with_preference_keyed(
            &signing_key,
            &key.key_id,
            inbox_url,
            body,
            &date_header,
            now,
            &self.capability_cache,
            self.default_format,
        )?;
        let primary_format = primary.format();

        let outcome = self.post_with_retries(inbox_url, body, primary).await;
        match outcome {
            DeliveryOutcome::Success { status, attempts } => Ok(DeliveryReport {
                format_used: primary_format,
                status,
                attempts,
            }),
            DeliveryOutcome::Unauthorized => {
                // 401 → flip format once, retry once.
                let secondary_format = flip_format(primary_format);
                let secondary = sign_post_with_format_keyed(
                    &signing_key,
                    &key.key_id,
                    inbox_url,
                    body,
                    &date_header,
                    now,
                    secondary_format,
                )?;
                match self.post_once(inbox_url, body, secondary).await {
                    DeliveryOutcome::Success {
                        status,
                        attempts: _,
                    } => {
                        // #174 failure-aware capability-cache correction:
                        // the cached/default format just 401'd and the flip
                        // worked, so record the working format for this
                        // instance origin. Future deliveries start with it
                        // instead of paying a wasted 401 + flip on every
                        // send until the 24h TTL would have expired. A stale
                        // entry (peer changed negotiation) self-heals here.
                        if let Some(origin) = inbox_origin(inbox_url) {
                            self.capability_cache.observe(origin, secondary_format, now);
                        }
                        Ok(DeliveryReport {
                            format_used: secondary_format,
                            status,
                            attempts: 2,
                        })
                    }
                    DeliveryOutcome::Unauthorized => Err(DeliveryError::BothFormatsRejected),
                    DeliveryOutcome::ClientError { status } => {
                        Err(DeliveryError::ClientError { status })
                    }
                    DeliveryOutcome::ServerError { status } => Err(DeliveryError::ServerError {
                        status,
                        attempts: 2,
                    }),
                    DeliveryOutcome::Network(msg) => Err(DeliveryError::Http(msg)),
                }
            }
            DeliveryOutcome::ClientError { status } => Err(DeliveryError::ClientError { status }),
            DeliveryOutcome::ServerError { status } => Err(DeliveryError::ServerError {
                status,
                attempts: MAX_DELIVERY_ATTEMPTS,
            }),
            DeliveryOutcome::Network(msg) => Err(DeliveryError::Http(msg)),
        }
    }

    /// Attempt one POST + retry on 5xx/network up to
    /// [`MAX_DELIVERY_ATTEMPTS`] times. 401 / non-401 4xx are
    /// returned to the caller for higher-level handling (flip,
    /// fail-fast).
    async fn post_with_retries(
        &self,
        inbox_url: &url::Url,
        body: &[u8],
        signed: OutboundSignedHeaders,
    ) -> DeliveryOutcome {
        let mut last_outcome = DeliveryOutcome::Network("no attempts made".into());
        let mut backoff = INITIAL_BACKOFF;
        for attempt in 1..=MAX_DELIVERY_ATTEMPTS {
            // Each retry re-signs from the same `signed` headers
            // because RSA-PKCS#1 v1.5 is deterministic — the
            // signature bytes for a given (key, body, date,
            // created) are stable. The `date_header` + `created_unix`
            // are bound INTO the signature, so we cannot regenerate
            // a fresh `Date` per attempt without re-signing.
            let outcome = self.post_once(inbox_url, body, signed.clone()).await;
            match &outcome {
                DeliveryOutcome::Success {
                    status,
                    attempts: _,
                } => {
                    return DeliveryOutcome::Success {
                        status: *status,
                        attempts: attempt,
                    };
                }
                DeliveryOutcome::Unauthorized | DeliveryOutcome::ClientError { .. } => {
                    return outcome;
                }
                DeliveryOutcome::ServerError { .. } | DeliveryOutcome::Network(_) => {
                    last_outcome = outcome;
                    if attempt < MAX_DELIVERY_ATTEMPTS {
                        tokio::time::sleep(backoff).await;
                        backoff = backoff.saturating_mul(2);
                    }
                }
            }
        }
        last_outcome
    }

    /// One POST attempt. Stuffs `signed.into_request_headers()` as
    /// HTTP headers, sets `Content-Type:
    /// application/activity+json`, sends the body.
    async fn post_once(
        &self,
        inbox_url: &url::Url,
        body: &[u8],
        signed: OutboundSignedHeaders,
    ) -> DeliveryOutcome {
        let mut req = self
            .http
            .post(inbox_url.clone())
            .header(reqwest::header::CONTENT_TYPE, ACTIVITY_JSON_CONTENT_TYPE)
            .body(body.to_vec());
        for (name, value) in signed.into_request_headers() {
            req = req.header(name, value);
        }
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if (200..300).contains(&status) {
                    DeliveryOutcome::Success {
                        status,
                        attempts: 1,
                    }
                } else if status == 401 {
                    DeliveryOutcome::Unauthorized
                } else if (400..500).contains(&status) {
                    DeliveryOutcome::ClientError { status }
                } else {
                    DeliveryOutcome::ServerError { status }
                }
            }
            Err(e) => DeliveryOutcome::Network(format!("{e}")),
        }
    }
}

/// Validate that `inbox` is a sane destination to sign-and-POST to.
///
/// **Stage 2.2 baseline** (the deliberate decision Alice's I1 asked
/// be recorded): structural-only checks — destination has a host,
/// uses `http(s)` scheme, `actor_url` has a host. Cross-origin
/// delivery is **not** filtered here (Mastodon is inherently
/// cross-instance). Real trust-list / follower-collection rules
/// arrive in Stage 4 via `fetchit_trust::EntryKind::ActorUrl`
/// denylist consultation.
///
/// `actor_url` is reserved for forward-compat with Stage 4 + so the
/// receiver can identify which actor identity the destination is
/// being `POSTed` under. We validate its host but do not gate
/// cross-origin in 2.2.
///
/// # Errors
/// Returns a `String` describing why the URL was refused.
pub fn validate_delivery_url(inbox: &url::Url, actor_url: &url::Url) -> Result<(), String> {
    if inbox.host_str().is_none() {
        return Err(format!("destination has no host: {inbox}"));
    }
    if !matches!(inbox.scheme(), "https" | "http") {
        return Err(format!(
            "destination scheme {} is not http(s): {inbox}",
            inbox.scheme()
        ));
    }
    if actor_url.host_str().is_none() {
        return Err(format!("actor URL has no host: {actor_url}"));
    }
    if !matches!(actor_url.scheme(), "https" | "http") {
        return Err(format!(
            "actor URL scheme {} is not http(s): {actor_url}",
            actor_url.scheme()
        ));
    }
    Ok(())
}

/// Format `now` as an IMF-fixdate / RFC 7231 §7.1.1.1 `Date` header
/// value (e.g. `"Sun, 06 Nov 1994 08:49:37 GMT"`).
///
/// Implemented locally rather than pulling in `httpdate` or `chrono`
/// to keep the dep tree thin — fetchit-fedi is the only consumer.
/// The civil-from-days algorithm is from Howard Hinnant's
/// `<https://howardhinnant.github.io/date_algorithms.html>` and is
/// canonical — the `as` casts are safe within u64-representable
/// timestamps; the algorithm output is pinned by three golden tests
/// covering the Unix epoch, the RFC 7231 example, and 2024 Feb 29.
#[must_use]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
pub fn format_imf_fixdate(now: SystemTime) -> String {
    let secs = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    // Days-since-epoch + seconds-of-day.
    let days = secs / 86_400;
    let secs_of_day = secs % 86_400;
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;

    // Day-of-week: 1970-01-01 was a Thursday.
    let dow = ((days + 4) % 7) as usize;
    let day_names = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

    // Civil-from-days algorithm (Hinnant, https://howardhinnant.github.io/date_algorithms.html).
    let z = days as i64 + 719_468;
    let era = if z >= 0 {
        z / 146_097
    } else {
        (z - 146_096) / 146_097
    };
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    let month_names = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let month_name = month_names[(m as usize) - 1];

    format!(
        "{dow}, {day:02} {month} {year:04} {hour:02}:{minute:02}:{second:02} GMT",
        dow = day_names[dow],
        day = d,
        month = month_name,
        year = y,
    )
}

fn flip_format(f: SignatureFormat) -> SignatureFormat {
    match f {
        SignatureFormat::Cavage => SignatureFormat::Rfc9421,
        SignatureFormat::Rfc9421 => SignatureFormat::Cavage,
    }
}

#[derive(Clone, Debug)]
enum DeliveryOutcome {
    Success { status: u16, attempts: u32 },
    Unauthorized,
    ClientError { status: u16 },
    ServerError { status: u16 },
    Network(String),
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use rsa::rand_core::OsRng;
    use std::sync::OnceLock;
    use wiremock::matchers::{header, header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_key() -> &'static HttpSignatureKey {
        static KEY: OnceLock<HttpSignatureKey> = OnceLock::new();
        KEY.get_or_init(|| {
            let priv_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
            let priv_pem = priv_key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
            HttpSignatureKey {
                key_id: "https://etchit.io/actors/josh#main-key".into(),
                rsa_private_pem: priv_pem,
            }
        })
    }

    fn actor_url() -> url::Url {
        "https://etchit.io/actors/josh".parse().unwrap()
    }

    fn fast_transport() -> FediverseTransport {
        // No body-sleeps in tests: short timeout + minimal retry
        // backoff via a separate constant would be cleaner, but
        // the production INITIAL_BACKOFF is small enough (1s) that
        // a 5xx-exhausted test runs in ~3s end-to-end.
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        FediverseTransport::with_client(
            http,
            Arc::new(SignatureCapabilityCache::new()),
            SignatureFormat::Cavage,
        )
    }

    #[test]
    fn validate_delivery_url_accepts_https() {
        let dest: url::Url = "https://example.com/inbox".parse().unwrap();
        validate_delivery_url(&dest, &actor_url()).unwrap();
    }

    #[test]
    fn validate_delivery_url_accepts_http_for_local_dev() {
        // Allowed for tests + local dev (wiremock binds http://127.0.0.1).
        // Stage 4 narrows to https-only via trust-list filtering.
        let dest: url::Url = "http://127.0.0.1:8080/inbox".parse().unwrap();
        validate_delivery_url(&dest, &actor_url()).unwrap();
    }

    #[test]
    fn validate_delivery_url_rejects_file_scheme() {
        // file:// has no host either, so either of the two early
        // checks may fire — both are valid rejections.
        let dest: url::Url = "file:///tmp/inbox".parse().unwrap();
        let err = validate_delivery_url(&dest, &actor_url()).unwrap_err();
        assert!(
            err.contains("not http(s)") || err.contains("no host"),
            "got: {err}"
        );
    }

    #[test]
    fn validate_delivery_url_rejects_ftp_with_host() {
        // FTP-with-host hits the scheme check (host is present).
        let dest: url::Url = "ftp://example.com/inbox".parse().unwrap();
        let err = validate_delivery_url(&dest, &actor_url()).unwrap_err();
        assert!(err.contains("not http(s)"), "got: {err}");
    }

    #[test]
    fn validate_delivery_url_rejects_destination_without_host() {
        // mailto: has no host component.
        let dest: url::Url = "mailto:noone@nowhere".parse().unwrap();
        let err = validate_delivery_url(&dest, &actor_url()).unwrap_err();
        assert!(err.contains("not http(s)") || err.contains("no host"));
    }

    #[test]
    fn validate_delivery_url_rejects_actor_without_host() {
        let dest: url::Url = "https://example.com/inbox".parse().unwrap();
        let bad_actor: url::Url = "file:///tmp/actor".parse().unwrap();
        let err = validate_delivery_url(&dest, &bad_actor).unwrap_err();
        assert!(err.contains("actor URL"), "got: {err}");
    }

    #[test]
    fn signing_key_cache_decodes_once() {
        let key = test_key();
        let cache = SigningKeyCache::new();
        let first = cache.get_or_decode(key).unwrap();
        let second = cache.get_or_decode(key).unwrap();
        assert!(
            Arc::ptr_eq(&first, &second),
            "second call must return the cached Arc, not a fresh decode"
        );
    }

    #[test]
    fn signing_key_cache_separates_distinct_key_ids() {
        let key_a = test_key();
        let key_b = HttpSignatureKey {
            key_id: "https://etchit.io/actors/alice#main-key".into(),
            rsa_private_pem: key_a.rsa_private_pem.clone(),
        };
        let cache = SigningKeyCache::new();
        let a = cache.get_or_decode(key_a).unwrap();
        let b = cache.get_or_decode(&key_b).unwrap();
        // Different key_id => independent cache slots even if the
        // PEM happens to be the same.
        assert!(!Arc::ptr_eq(&a, &b));
        // Re-fetch of A still returns the original Arc.
        let a_again = cache.get_or_decode(key_a).unwrap();
        assert!(Arc::ptr_eq(&a, &a_again));
    }

    #[test]
    fn signing_key_cache_invalid_pem_surfaces_error() {
        let cache = SigningKeyCache::new();
        let bad = HttpSignatureKey {
            key_id: "https://etchit.io/actors/bad#main-key".into(),
            rsa_private_pem: "not a PEM".into(),
        };
        let err = cache.get_or_decode(&bad).unwrap_err();
        assert!(matches!(err, HttpSignatureError::InvalidPrivateKey(_)));
    }

    #[test]
    fn flip_format_is_involution() {
        assert_eq!(
            flip_format(flip_format(SignatureFormat::Cavage)),
            SignatureFormat::Cavage
        );
        assert_eq!(
            flip_format(flip_format(SignatureFormat::Rfc9421)),
            SignatureFormat::Rfc9421
        );
        assert_ne!(
            flip_format(SignatureFormat::Cavage),
            SignatureFormat::Cavage
        );
    }

    #[test]
    fn format_imf_fixdate_known_unix_epoch() {
        // The Unix epoch is Thursday, 01 Jan 1970 00:00:00 GMT.
        let d = format_imf_fixdate(SystemTime::UNIX_EPOCH);
        assert_eq!(d, "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[test]
    fn format_imf_fixdate_known_dilbert_birthday() {
        // 1994-11-06 08:49:37 UTC is the canonical example from RFC 7231
        // (a Sunday). Unix seconds = 784111777.
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(784_111_777);
        let d = format_imf_fixdate(t);
        assert_eq!(d, "Sun, 06 Nov 1994 08:49:37 GMT");
    }

    #[test]
    fn format_imf_fixdate_leap_year_feb_29() {
        // 2024-02-29 12:00:00 UTC (Thursday) — pins the civil-from-days
        // algo handles leap years correctly.
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_709_208_000);
        let d = format_imf_fixdate(t);
        assert_eq!(d, "Thu, 29 Feb 2024 12:00:00 GMT");
    }

    /// Build a `url::Url` from a `MockServer` URI. wiremock returns
    /// `http://127.0.0.1:NNNN` so we just append the path.
    fn inbox_url(server: &MockServer, path_str: &str) -> url::Url {
        format!("{}{}", server.uri(), path_str).parse().unwrap()
    }

    #[tokio::test]
    async fn deliver_succeeds_on_200() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/inbox"))
            .and(header_exists("date"))
            .and(header_exists("signature"))
            .and(header(
                reqwest::header::CONTENT_TYPE.as_str(),
                ACTIVITY_JSON_CONTENT_TYPE,
            ))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let transport = fast_transport();
        let url = inbox_url(&server, "/inbox");
        let report = transport
            .deliver(test_key(), br#"{"type":"Create"}"#, &url, &actor_url())
            .await
            .unwrap();
        assert_eq!(report.status, 200);
        assert_eq!(report.attempts, 1);
        assert_eq!(report.format_used, SignatureFormat::Cavage);
    }

    #[tokio::test]
    async fn deliver_succeeds_on_202_accepted() {
        // Mastodon's actual inbox response on a queued activity.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/inbox"))
            .respond_with(ResponseTemplate::new(202))
            .expect(1)
            .mount(&server)
            .await;

        let transport = fast_transport();
        let url = inbox_url(&server, "/inbox");
        let report = transport
            .deliver(test_key(), b"{}", &url, &actor_url())
            .await
            .unwrap();
        assert_eq!(report.status, 202);
        assert_eq!(report.attempts, 1);
    }

    #[tokio::test]
    async fn deliver_flips_to_other_format_on_401() {
        // First attempt (cavage default) gets 401; receiver only
        // honours RFC 9421's `Signature-Input` header. We flip and
        // succeed on attempt 2.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/inbox"))
            // First attempt's cavage signature has NO Signature-Input
            // header. Match requests that lack it => 401.
            .and(header_exists("signature"))
            // Reject the first cavage request: NO Signature-Input.
            .respond_with(ResponseTemplate::new(401))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        // Second attempt sends Signature-Input + Content-Digest;
        // accept it.
        Mock::given(method("POST"))
            .and(path("/inbox"))
            .and(header_exists("signature-input"))
            .and(header_exists("content-digest"))
            .respond_with(ResponseTemplate::new(202))
            .expect(1)
            .mount(&server)
            .await;

        let transport = fast_transport();
        let url = inbox_url(&server, "/inbox");
        let report = transport
            .deliver(test_key(), b"{}", &url, &actor_url())
            .await
            .unwrap();
        assert_eq!(report.format_used, SignatureFormat::Rfc9421);
        assert_eq!(report.attempts, 2);
        assert_eq!(report.status, 202);
    }

    #[tokio::test]
    async fn deliver_flip_success_corrects_capability_cache() {
        // #174: a 401-on-default followed by a flip-success must write the
        // working format back to the capability cache, so the next delivery
        // to this instance starts with it instead of repeating a wasted
        // 401 + flip on every send for the 24h TTL.
        let server = MockServer::start().await;
        // First (cavage default) attempt → 401.
        Mock::given(method("POST"))
            .and(path("/inbox"))
            .and(header_exists("signature"))
            .respond_with(ResponseTemplate::new(401))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        // Flip to RFC 9421 → accept.
        Mock::given(method("POST"))
            .and(path("/inbox"))
            .and(header_exists("signature-input"))
            .respond_with(ResponseTemplate::new(202))
            .expect(1)
            .mount(&server)
            .await;

        let transport = fast_transport();
        let url = inbox_url(&server, "/inbox");
        let origin = inbox_origin(&url).unwrap();

        // Cache is cold before delivery.
        assert!(
            transport
                .capability_cache()
                .preference(&origin, SystemTime::now())
                .is_none(),
            "cache must start cold for this origin",
        );

        let report = transport
            .deliver(test_key(), b"{}", &url, &actor_url())
            .await
            .unwrap();
        assert_eq!(report.format_used, SignatureFormat::Rfc9421);

        // The flip-success wrote the working format back.
        assert_eq!(
            transport
                .capability_cache()
                .preference(&origin, SystemTime::now()),
            Some(SignatureFormat::Rfc9421),
            "flip-success must correct the capability cache to the working format",
        );
    }

    #[tokio::test]
    async fn deliver_first_attempt_success_leaves_cache_cold() {
        // #174 scope guard: a clean first-attempt success must NOT write
        // the cache — only a failure-driven flip corrects it. (Affirmative
        // "prefers" signals come from the Stage 3 inbox-response path, not
        // from every successful POST.)
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/inbox"))
            .respond_with(ResponseTemplate::new(202))
            .expect(1)
            .mount(&server)
            .await;

        let transport = fast_transport();
        let url = inbox_url(&server, "/inbox");
        let origin = inbox_origin(&url).unwrap();

        transport
            .deliver(test_key(), b"{}", &url, &actor_url())
            .await
            .unwrap();
        assert!(
            transport
                .capability_cache()
                .preference(&origin, SystemTime::now())
                .is_none(),
            "first-attempt success must not write the capability cache",
        );
    }

    #[tokio::test]
    async fn deliver_returns_both_formats_rejected_on_double_401() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/inbox"))
            .respond_with(ResponseTemplate::new(401))
            .expect(2)
            .mount(&server)
            .await;

        let transport = fast_transport();
        let url = inbox_url(&server, "/inbox");
        let err = transport
            .deliver(test_key(), b"{}", &url, &actor_url())
            .await
            .unwrap_err();
        assert!(
            matches!(err, DeliveryError::BothFormatsRejected),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn deliver_returns_client_error_without_retry_on_400() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/inbox"))
            .respond_with(ResponseTemplate::new(400))
            .expect(1) // EXACTLY one — no retry on 4xx.
            .mount(&server)
            .await;

        let transport = fast_transport();
        let url = inbox_url(&server, "/inbox");
        let err = transport
            .deliver(test_key(), b"{}", &url, &actor_url())
            .await
            .unwrap_err();
        assert!(
            matches!(err, DeliveryError::ClientError { status: 400 }),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn deliver_returns_client_error_without_retry_on_410_gone() {
        // 410 Gone is what Mastodon returns when an actor has been
        // deleted — must NOT retry.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/inbox"))
            .respond_with(ResponseTemplate::new(410))
            .expect(1)
            .mount(&server)
            .await;

        let transport = fast_transport();
        let url = inbox_url(&server, "/inbox");
        let err = transport
            .deliver(test_key(), b"{}", &url, &actor_url())
            .await
            .unwrap_err();
        assert!(
            matches!(err, DeliveryError::ClientError { status: 410 }),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn deliver_retries_on_5xx_then_surfaces_server_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/inbox"))
            .respond_with(ResponseTemplate::new(503))
            .expect(u64::from(MAX_DELIVERY_ATTEMPTS))
            .mount(&server)
            .await;

        let transport = fast_transport();
        let url = inbox_url(&server, "/inbox");
        let err = transport
            .deliver(test_key(), b"{}", &url, &actor_url())
            .await
            .unwrap_err();
        match err {
            DeliveryError::ServerError { status, attempts } => {
                assert_eq!(status, 503);
                assert_eq!(attempts, MAX_DELIVERY_ATTEMPTS);
            }
            other => panic!("expected ServerError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn deliver_recovers_on_503_then_200() {
        // First attempt 503, second 200 — succeeds on attempt 2.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/inbox"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/inbox"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let transport = fast_transport();
        let url = inbox_url(&server, "/inbox");
        let report = transport
            .deliver(test_key(), b"{}", &url, &actor_url())
            .await
            .unwrap();
        assert_eq!(report.status, 200);
        assert_eq!(report.attempts, 2);
    }

    #[tokio::test]
    async fn deliver_refuses_invalid_destination_before_signing() {
        // file:// has no host. Validation must reject before any
        // signing/network work happens.
        let transport = fast_transport();
        let bad: url::Url = "file:///tmp/inbox".parse().unwrap();
        let err = transport
            .deliver(test_key(), b"{}", &bad, &actor_url())
            .await
            .unwrap_err();
        assert!(matches!(err, DeliveryError::InvalidDeliveryUrl(_)));
    }

    #[tokio::test]
    async fn deliver_uses_cached_preference_when_present() {
        // Pre-populate the cache: this peer prefers Rfc9421.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/inbox"))
            .and(header_exists("signature-input"))
            .and(header_exists("content-digest"))
            .respond_with(ResponseTemplate::new(202))
            .expect(1)
            .mount(&server)
            .await;

        let cache = Arc::new(SignatureCapabilityCache::new());
        let url = inbox_url(&server, "/inbox");
        // inbox_origin returns scheme://host:port (port is non-default
        // for wiremock); observe under that key.
        if let Some(origin) = crate::signature_cache::inbox_origin(&url) {
            cache.observe(origin, SignatureFormat::Rfc9421, SystemTime::now());
        }

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let transport = FediverseTransport::with_client(http, cache, SignatureFormat::Cavage);

        let report = transport
            .deliver(test_key(), b"{}", &url, &actor_url())
            .await
            .unwrap();
        assert_eq!(report.format_used, SignatureFormat::Rfc9421);
        assert_eq!(report.attempts, 1);
    }
}
