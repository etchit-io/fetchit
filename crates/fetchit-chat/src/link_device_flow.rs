//! Publish + fetch a sealed link-device offer over the relay blob store
//! (`/v1/blob`), the transport half of M6.4 enrollment.
//!
//! The new device seals its [`LinkDeviceOffer`], PUTs the opaque ciphertext to
//! a relay under a fresh random token, and hands out the compact pointer URI
//! (the QR). The existing device parses the pointer, GETs the ciphertext by
//! token, opens it, and structurally validates the offer. The relay only ever
//! holds opaque bytes under an opaque token — the blind-relay posture.
//!
//! The HTTP shape mirrors [`crate::pair_record`]: [`guard_relay_url`] gates the
//! URL, [`relay_send_with_retry`] wraps the request, and the offer's own
//! `exp_ms` (checked client-side on open, not by the relay) is the real
//! freshness gate.
//!
//! [`guard_relay_url`]: crate::relay_http::guard_relay_url
//! [`relay_send_with_retry`]: crate::relay_http::relay_send_with_retry

use crate::chat_crypto::{random_nonce, AEAD_KEY_LEN};
use crate::error::ChatError;
use crate::link_device::LinkDeviceOffer;
use crate::link_device_uri::{emit_link_device_uri, parse_link_device_uri};
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
        use fetchit_relay_server::{Server, ServerConfig};

        // Probe a free loopback port, then let the real relay re-bind it and
        // serve the production /v1/blob route (store + serve + sweeper).
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound = probe.local_addr().unwrap();
        drop(probe);
        tokio::spawn(async move {
            let _ = Server::new(ServerConfig::defaults(bound, Region::Nyc))
                .run()
                .await;
        });
        tokio::time::sleep(Duration::from_millis(150)).await;

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
}
