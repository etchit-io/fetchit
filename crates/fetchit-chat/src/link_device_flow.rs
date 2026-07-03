//! Publish + fetch a sealed link-device offer over the relay blob store
//! (`/v1/blob`), the transport half of M6.4 enrollment.
//!
//! The new device seals its [`LinkDeviceOffer`], PUTs the opaque ciphertext to
//! a relay under a fresh random token, and hands out the compact pointer URI
//! (the QR). The existing device parses the pointer, GETs the ciphertext by
//! token, opens it, and structurally validates the offer. The relay only ever
//! holds opaque bytes under an opaque token — the blind-relay posture.
//!
//! The HTTP shape mirrors [`crate::pair_record`]: `guard_relay_url` gates the
//! URL, `relay_send_with_retry` wraps the request, and the offer's own
//! `exp_ms` (checked client-side on open, not by the relay) is the real
//! freshness gate.

use crate::chat_crypto::{random_nonce, AEAD_KEY_LEN};
use crate::error::ChatError;
use crate::link_device::LinkDeviceOffer;
use crate::link_device_uri::{emit_link_device_uri, parse_link_device_uri};
use base64::engine::general_purpose::STANDARD as B64STD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;
use std::time::Duration;

/// Random bytes in the relay-storage token (base64url in the URI). 24 bytes →
/// 32 base64url chars, an unguessable capability within the URI's 16..=48-byte
/// decoded token bounds.
const TOKEN_BYTES: usize = 24;

/// Per-request timeout for a blob PUT/GET.
const BLOB_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Read cap when fetching a blob: 2× the relay's 128 KB store cap, ample for
/// the sealed offer (~3.3 KB) with headroom, and a guard against a hostile
/// relay streaming unbounded bytes.
const MAX_LINK_BLOB_BYTES: usize = 256 * 1024;

/// Bytes of random in a fresh offer's one-time nonce (within the offer's
/// 16..=64-byte decoded bound).
const LINK_OFFER_NONCE_BYTES: usize = 16;

/// The new device's published link offer: the QR pointer to encode, plus the
/// short-code to show beside it for the human comparison, plus the expiry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatedLinkOffer {
    /// `fetchit://link/v1/…` pointer to encode as the QR.
    pub uri: String,
    /// Human-comparable confirm code (`XXXX-XXXX`) shown beside the QR.
    pub short_code: String,
    /// Absolute expiry, epoch milliseconds.
    pub exp_ms: u64,
}

/// What the existing device shows on its confirm screen after scanning: the
/// new device's agent id, the short-code to compare against the new device's
/// screen, and whether the offer has already expired.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkOfferPreview {
    /// The new device's agent id (hex).
    pub agent_id_hex: String,
    /// Human-comparable confirm code (`XXXX-XXXX`).
    pub short_code: String,
    /// `true` when the offer is past its expiry at the caller's clock.
    pub expired: bool,
}

/// Seal `offer` and publish it, returning the pointer URI to encode in the QR.
///
/// Generates a fresh single-use seal key, nonce, and storage token; seals the
/// offer; PUTs the ciphertext to every reachable `relay` (redundancy); and
/// emits `fetchit://link/v1/<token>?r=<relay>...#k=<key>` listing the relays
/// that accepted it. The seal key rides the URI fragment — never sent to a
/// relay.
///
/// # Errors
/// [`ChatError`] if sealing fails, no relay accepts the blob, or the resulting
/// URI fails to build (e.g. too many relays).
pub async fn publish_link_offer(
    offer: &LinkDeviceOffer,
    relays: &[String],
    http: &reqwest::Client,
) -> Result<String, ChatError> {
    let mut rng = OsRng;
    let mut key = [0u8; AEAD_KEY_LEN];
    rng.fill_bytes(&mut key);
    let nonce = random_nonce(&mut rng);
    let mut token_bytes = [0u8; TOKEN_BYTES];
    rng.fill_bytes(&mut token_bytes);
    let token = B64URL.encode(token_bytes);

    let blob = offer.seal(&key, &nonce)?;

    let mut stored_on = Vec::new();
    let mut last_err = None;
    for relay in relays {
        match put_blob(relay, &token, &blob, http).await {
            Ok(()) => stored_on.push(relay.clone()),
            Err(e) => last_err = Some(e),
        }
    }
    if stored_on.is_empty() {
        return Err(last_err
            .unwrap_or_else(|| ChatError::Invalid("no relays accepted the link offer".into())));
    }

    emit_link_device_uri(&token, &stored_on, &key)
        .map_err(|e| ChatError::Invalid(format!("emit link uri: {e}")))
}

/// Fetch and open the offer a `uri` points at. Parses the pointer, GETs the
/// sealed blob from the first relay that serves it, opens it with the fragment
/// key, and structurally [`validate`](LinkDeviceOffer::validate)s it.
///
/// Freshness is **not** checked here — the caller applies its own clock via
/// [`LinkDeviceOffer::is_expired`] alongside the human short-code confirmation.
///
/// # Errors
/// [`ChatError`] on a malformed URI, no relay serving the blob, a decrypt
/// failure (tampering or wrong key), or a structurally invalid offer.
pub async fn fetch_link_offer(
    uri: &str,
    http: &reqwest::Client,
) -> Result<LinkDeviceOffer, ChatError> {
    let parsed = parse_link_device_uri(uri)
        .map_err(|e| ChatError::Invalid(format!("parse link uri: {e}")))?;

    let mut blob = None;
    let mut last_err = None;
    for relay in &parsed.relays {
        match get_blob(relay, &parsed.token, http).await {
            Ok(Some(b)) => {
                blob = Some(b);
                break;
            }
            Ok(None) => {
                last_err = Some(ChatError::Invalid(
                    "relay has no blob for this link (expired or wrong token)".into(),
                ));
            }
            Err(e) => last_err = Some(e),
        }
    }
    let blob = blob.ok_or_else(|| {
        last_err.unwrap_or_else(|| ChatError::Invalid("no relays served the link offer".into()))
    })?;

    let offer = LinkDeviceOffer::open(&blob, &parsed.key)?;
    offer
        .validate()
        .map_err(|e| ChatError::Invalid(format!("invalid link offer: {e}")))?;
    Ok(offer)
}

/// New-device side: mint an offer for this device (`agent_id_hex` + its raw
/// ML-DSA and ML-KEM keys), publish it, and return the QR pointer + the
/// short-code to display. Generates a fresh single-use nonce; `exp_ms` is the
/// offer's absolute expiry (the caller passes now + a short enrollment window).
///
/// # Errors
/// [`ChatError`] if sealing fails or no relay accepts the offer.
pub async fn create_link_offer(
    agent_id_hex: String,
    agent_ml_dsa_pubkey: &[u8],
    kem_pubkey: &[u8],
    relays: &[String],
    exp_ms: u64,
    http: &reqwest::Client,
) -> Result<CreatedLinkOffer, ChatError> {
    let mut nonce = [0u8; LINK_OFFER_NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);
    let offer = LinkDeviceOffer::mint(
        agent_id_hex,
        agent_ml_dsa_pubkey,
        kem_pubkey,
        &nonce,
        exp_ms,
    );
    let short_code = offer.short_code();
    let uri = publish_link_offer(&offer, relays, http).await?;
    Ok(CreatedLinkOffer {
        uri,
        short_code,
        exp_ms,
    })
}

/// Existing-device side: fetch the offer a scanned `uri` points at and return
/// the confirm-screen preview (agent id + short-code + freshness at `now_ms`).
/// The full offer is validated during the fetch; the caller mints the cert
/// only after the human confirms the short-code matches.
///
/// # Errors
/// [`ChatError`] on a malformed URI, no relay serving the blob, a decrypt
/// failure, or a structurally invalid offer.
pub async fn preview_link_offer(
    uri: &str,
    now_ms: u64,
    http: &reqwest::Client,
) -> Result<LinkOfferPreview, ChatError> {
    let offer = fetch_link_offer(uri, http).await?;
    Ok(LinkOfferPreview {
        short_code: offer.short_code(),
        expired: offer.is_expired(now_ms),
        agent_id_hex: offer.agent_id_hex,
    })
}

/// Decode an offer's STANDARD-base64 ML-DSA + ML-KEM keys to raw bytes.
fn decode_offer_keys(offer: &LinkDeviceOffer) -> Result<(Vec<u8>, Vec<u8>), ChatError> {
    let ml_dsa = B64STD
        .decode(&offer.agent_ml_dsa_pubkey_b64)
        .map_err(|_| ChatError::Invalid("offer ml-dsa key is not base64".into()))?;
    let kem = B64STD
        .decode(&offer.kem_pubkey_b64)
        .map_err(|_| ChatError::Invalid("offer ml-kem key is not base64".into()))?;
    Ok((ml_dsa, kem))
}

/// Existing-device side: after the human confirms the short-code matches, mint
/// the account certificate for the scanned offer's device. Fetches + validates
/// the offer, then signs an
/// [`AgentCertificate`](crate::fabric::AgentCertificate) with the account user
/// key (unlocked from THIS device's vault via `passphrase`). Returns the cert
/// for the caller to publish in the account's `PairRecordV4` (revision N+1) and
/// deliver to the new device.
///
/// It does NOT persist to this device's `device_cert.json` — the cert belongs
/// to the newly linked device, not this one.
///
/// # Errors
/// [`ChatError`] on a bad URI / fetch, a wrong passphrase or missing
/// recoverable seed, or a malformed offer.
pub async fn confirm_link_device(
    data_dir: &std::path::Path,
    passphrase: Option<&str>,
    uri: &str,
    added_at_ms: u64,
    http: &reqwest::Client,
) -> Result<crate::fabric::AgentCertificate, ChatError> {
    let offer = fetch_link_offer(uri, http).await?;
    let identity_vault = data_dir.join(crate::chat_identity::IDENTITY_FILE);
    let (master, _kdf_id, _argon_salt) =
        crate::client::resolve_master_key(&identity_vault, passphrase)?;
    confirm_offer_from_master(data_dir, &master, &offer, added_at_ms)
}

/// [`confirm_link_device`] with an already-fetched `offer` and an
/// already-resolved [`MasterKey`](crate::at_rest::MasterKey): the internal seam
/// the unit tests share (no relay round-trip, no passphrase prompt).
///
/// # Errors
/// As [`confirm_link_device`].
pub(crate) fn confirm_offer_from_master(
    data_dir: &std::path::Path,
    master: &crate::at_rest::MasterKey,
    offer: &LinkDeviceOffer,
    added_at_ms: u64,
) -> Result<crate::fabric::AgentCertificate, ChatError> {
    // Self-guard (Alice finding A): reject a stale offer BEFORE minting, so the
    // QR-swap short-code grind window is the offer's own short expiry, not the
    // ~1h relay blob TTL. `added_at_ms` is the confirm-time clock.
    if offer.is_expired(added_at_ms) {
        return Err(ChatError::Invalid(
            "link offer has expired; ask the new device for a fresh QR".into(),
        ));
    }
    let (ml_dsa, kem) = decode_offer_keys(offer)?;
    crate::local_signer::with_user_key_from_master(data_dir, master, |user| {
        crate::fabric::mint_agent_certificate(user, &offer.agent_id_hex, &ml_dsa, &kem, added_at_ms)
    })
}

/// POST the sealed `blob` to `<relay>/v1/blob/<token>` (raw body).
async fn put_blob(
    relay: &str,
    token: &str,
    blob: &[u8],
    http: &reqwest::Client,
) -> Result<(), ChatError> {
    let url = blob_url(relay, token).await?;
    let resp = crate::relay_http::relay_send_with_retry(|| {
        http.post(url.clone())
            .body(blob.to_vec())
            .timeout(BLOB_HTTP_TIMEOUT)
    })
    .await?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(ChatError::Invalid(format!(
            "relay returned {} storing link blob",
            resp.status().as_u16()
        )))
    }
}

/// GET `<relay>/v1/blob/<token>`; `Ok(None)` on 404 (absent/expired).
async fn get_blob(
    relay: &str,
    token: &str,
    http: &reqwest::Client,
) -> Result<Option<Vec<u8>>, ChatError> {
    let url = blob_url(relay, token).await?;
    let resp = crate::relay_http::relay_send_with_retry(|| {
        http.get(url.clone()).timeout(BLOB_HTTP_TIMEOUT)
    })
    .await?;
    if resp.status().as_u16() == 404 {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(ChatError::Invalid(format!(
            "relay returned {} fetching link blob",
            resp.status().as_u16()
        )));
    }
    let bytes = crate::relay_http::read_body_capped(resp, MAX_LINK_BLOB_BYTES)
        .await
        .map_err(|e| ChatError::Invalid(e.to_string()))?;
    Ok(Some(bytes))
}

/// SSRF-guard `relay` and join `v1/blob/<token>` onto it.
async fn blob_url(relay: &str, token: &str) -> Result<url::Url, ChatError> {
    let base = url::Url::parse(relay).map_err(|e| ChatError::Invalid(format!("relay url: {e}")))?;
    crate::relay_http::guard_relay_url(&base)
        .await
        .map_err(|e| ChatError::Invalid(format!("relay blocked: {e}")))?;
    base.join(&format!("v1/blob/{token}"))
        .map_err(|e| ChatError::Invalid(format!("build blob url: {e}")))
}

/// Bring up a real `fetchit-relay-server` on a fresh loopback port for the
/// crate's e2e tests, returning its bound address once it is actually serving.
///
/// Probes a free `:0` port, drops it, and lets the server rebind it (the relay
/// binds a fixed `SocketAddr` and never reports a `:0`-assigned port), then
/// polls a connect until the main listener accepts -- a readiness check rather
/// than a blind sleep, so a slow box does not race the first request.
///
/// Crucially it sets `internal_bind = None`. `ServerConfig::defaults` binds a
/// FIXED loopback internal-metrics port (127.0.0.1:9088), so two concurrent
/// test servers collide on it: the second's `run()` returns `Err` at that bind
/// and drops its already-bound main listener, and requests to that main port
/// then get `ConnectionRefused`. The e2e tests never touch the internal
/// channel, so disabling it lets any number of relays run concurrently.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) async fn spawn_ephemeral_relay(
    region: fetchit_relay_proto::Region,
) -> std::net::SocketAddr {
    use fetchit_relay_server::{Server, ServerConfig};
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bound = probe.local_addr().unwrap();
    drop(probe);
    let mut config = ServerConfig::defaults(bound, region);
    config.internal_bind = None;
    tokio::spawn(async move {
        let _ = Server::new(config).run().await;
    });
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(bound).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    bound
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::chat_crypto::AEAD_NONCE_LEN;
    use base64::engine::general_purpose::STANDARD as B64STD;
    use fetchit_relay_client::{MlDsaSigner, Signer};
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// A well-formed offer whose agent id binds its (real) ML-DSA key, so
    /// [`LinkDeviceOffer::validate`] on the fetch path passes.
    fn sample_offer() -> LinkDeviceOffer {
        let signer = MlDsaSigner::from_seed(&[3u8; 32]);
        LinkDeviceOffer {
            agent_id_hex: hex::encode(signer.agent_id()),
            agent_ml_dsa_pubkey_b64: B64STD.encode(signer.public_key()),
            kem_pubkey_b64: B64STD.encode([0u8; 1184]),
            nonce_b64: B64STD.encode([7u8; 16]),
            exp_ms: 1_800_000_000_000,
        }
    }

    fn token() -> String {
        B64URL.encode([9u8; TOKEN_BYTES])
    }

    #[tokio::test]
    async fn fetch_opens_a_served_blob() {
        let offer = sample_offer();
        let key = [0x33; AEAD_KEY_LEN];
        let blob = offer.seal(&key, &[0x44; AEAD_NONCE_LEN]).unwrap();
        let tok = token();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/blob/{tok}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(blob))
            .mount(&server)
            .await;

        let uri = emit_link_device_uri(&tok, &[server.uri()], &key).unwrap();
        let got = fetch_link_offer(&uri, &crate::relay_http::guarded_client())
            .await
            .unwrap();
        assert_eq!(got, offer);
    }

    #[tokio::test]
    async fn fetch_errors_when_the_blob_is_absent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let uri = emit_link_device_uri(&token(), &[server.uri()], &[0x33; AEAD_KEY_LEN]).unwrap();
        assert!(fetch_link_offer(&uri, &crate::relay_http::guarded_client())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn fetch_rejects_a_tampered_blob() {
        let offer = sample_offer();
        let key = [0x33; AEAD_KEY_LEN];
        let mut blob = offer.seal(&key, &[0x44; AEAD_NONCE_LEN]).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(blob))
            .mount(&server)
            .await;
        let uri = emit_link_device_uri(&token(), &[server.uri()], &key).unwrap();
        assert!(fetch_link_offer(&uri, &crate::relay_http::guarded_client())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn publish_stores_and_returns_a_pointer_uri() {
        let offer = sample_offer();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/v1/blob/.+"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let uri = publish_link_offer(
            &offer,
            &[server.uri()],
            &crate::relay_http::guarded_client(),
        )
        .await
        .unwrap();
        assert!(uri.starts_with("fetchit://link/v1/"), "got {uri}");
        // The emitted pointer round-trips through the parser.
        let parsed = parse_link_device_uri(&uri).unwrap();
        assert_eq!(parsed.relays.len(), 1);
    }

    #[tokio::test]
    async fn published_uri_is_self_consistently_fetchable() {
        // publish emits a URI carrying (token, seal key). Prove they cohere: a
        // blob sealed under that key and served at that token opens back to the
        // offer via fetch. A true store-and-serve round-trip needs a stateful
        // backend — the real relay-server e2e covers that leg.
        let offer = sample_offer();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/v1/blob/.+"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let uri = publish_link_offer(
            &offer,
            &[server.uri()],
            &crate::relay_http::guarded_client(),
        )
        .await
        .unwrap();
        let parsed = parse_link_device_uri(&uri).unwrap();
        let blob = offer.seal(&parsed.key, &[0u8; AEAD_NONCE_LEN]).unwrap();
        Mock::given(method("GET"))
            .and(path(format!("/v1/blob/{}", parsed.token)))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(blob))
            .mount(&server)
            .await;
        let got = fetch_link_offer(&uri, &crate::relay_http::guarded_client())
            .await
            .unwrap();
        assert_eq!(got, offer);
    }

    #[tokio::test]
    async fn publish_errors_when_every_relay_rejects() {
        let offer = sample_offer();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        assert!(publish_link_offer(
            &offer,
            &[server.uri()],
            &crate::relay_http::guarded_client()
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn e2e_round_trips_through_a_real_relay_server() {
        use fetchit_relay_proto::Region;

        // Bring up the real relay serving the production /v1/blob route on a
        // fresh loopback port (serialized to dodge the probe/rebind port race).
        let bound = spawn_ephemeral_relay(Region::Nyc).await;

        // A true round-trip: publish PUTs the sealed blob to the live relay,
        // fetch GETs it back, opens it with the fragment key, and validates.
        let offer = sample_offer();
        let http = crate::relay_http::guarded_client();
        let uri = publish_link_offer(&offer, &[format!("http://{bound}")], &http)
            .await
            .unwrap();
        let got = fetch_link_offer(&uri, &http).await.unwrap();
        assert_eq!(got, offer);
    }

    #[tokio::test]
    async fn create_link_offer_publishes_and_returns_a_short_code() {
        let signer = MlDsaSigner::from_seed(&[21u8; 32]);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/v1/blob/.+"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let created = create_link_offer(
            hex::encode(signer.agent_id()),
            &signer.public_key(),
            &[0u8; 1184],
            &[server.uri()],
            1_800_000_000_000,
            &crate::relay_http::guarded_client(),
        )
        .await
        .unwrap();
        assert!(
            created.uri.starts_with("fetchit://link/v1/"),
            "{}",
            created.uri
        );
        assert_eq!(created.short_code.len(), 14, "XXXX-XXXX-XXXX");
        assert_eq!(created.exp_ms, 1_800_000_000_000);
    }

    #[tokio::test]
    async fn preview_link_offer_returns_identity_and_freshness() {
        let offer = sample_offer();
        let key = [0x71; AEAD_KEY_LEN];
        let blob = offer.seal(&key, &[0x99; AEAD_NONCE_LEN]).unwrap();
        let tok = token();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/blob/{tok}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(blob))
            .mount(&server)
            .await;
        let uri = emit_link_device_uri(&tok, &[server.uri()], &key).unwrap();
        let http = crate::relay_http::guarded_client();

        let fresh = preview_link_offer(&uri, 1_000, &http).await.unwrap();
        assert_eq!(fresh.agent_id_hex, offer.agent_id_hex);
        assert_eq!(fresh.short_code, offer.short_code());
        assert!(!fresh.expired);

        let past = preview_link_offer(&uri, offer.exp_ms + 1, &http)
            .await
            .unwrap();
        assert!(past.expired);
    }

    #[test]
    fn confirm_offer_from_master_mints_a_verifiable_cert() {
        use crate::at_rest::{fresh_argon_salt, kdf_id_argon2, MasterKey, MasterKeySource};
        use crate::fabric::verify_agent_certificate;
        use crate::local_signer::{with_user_key_from_master, LocalSignerVault};
        use zeroize::Zeroizing;

        let dir = tempfile::tempdir().unwrap();
        let salt = fresh_argon_salt();
        let master = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("p".into())),
            Some(&salt),
        )
        .unwrap();
        LocalSignerVault::load_or_create(dir.path(), &master, kdf_id_argon2(), Some(&salt))
            .unwrap();

        // The NEW device's offer — a different agent than this vault's identity.
        let signer = MlDsaSigner::from_seed(&[44u8; 32]);
        let offer = LinkDeviceOffer::mint(
            hex::encode(signer.agent_id()),
            &signer.public_key(),
            &[0u8; 1184],
            &[5u8; 16],
            1_700_000_000_000,
        );
        // Confirm clock (1.6e12) precedes the offer expiry (1.7e12): not expired.
        let cert =
            confirm_offer_from_master(dir.path(), &master, &offer, 1_600_000_000_000).unwrap();

        // Binds the new device's agent, signed by the account user key derived
        // from THIS device's vault.
        assert_eq!(cert.agent_id_hex, offer.agent_id_hex);
        let user_pk =
            with_user_key_from_master(dir.path(), &master, |u| Ok(u.public_key_bytes().to_vec()))
                .unwrap();
        verify_agent_certificate(&cert, &user_pk).unwrap();
    }

    #[test]
    fn confirm_rejects_an_expired_offer() {
        use crate::at_rest::{fresh_argon_salt, MasterKey, MasterKeySource};
        use zeroize::Zeroizing;

        // No vault load: the expiry check fires before any user-key use.
        let dir = tempfile::tempdir().unwrap();
        let salt = fresh_argon_salt();
        let master = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("p".into())),
            Some(&salt),
        )
        .unwrap();
        let signer = MlDsaSigner::from_seed(&[44u8; 32]);
        let offer = LinkDeviceOffer::mint(
            hex::encode(signer.agent_id()),
            &signer.public_key(),
            &[0u8; 1184],
            &[5u8; 16],
            1_000,
        );
        // The confirm clock (2_000) is past the offer's exp (1_000): reject.
        assert!(confirm_offer_from_master(dir.path(), &master, &offer, 2_000).is_err());
    }
}
