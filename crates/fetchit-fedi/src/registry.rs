//! Self-serve actor-registry client (M5.1, Component D).
//!
//! The JSON shapes here are a frozen wire contract shared with the
//! fediverse bridge server (`fetchit-relay-server` built with
//! `--features fediverse-inbox`); tests pin them against
//! `tests/fixtures/registry-v1/`. See the fixture README for the
//! server-side verification obligations (attestation verify,
//! first-come-first-served handles, same-agent-id continuity,
//! hint-epoch monotonicity).

use crate::attestation::{b64, ActorAttestationV2};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Per-call timeout for registry requests.
const REGISTRY_TIMEOUT: Duration = Duration::from_secs(10);

/// Registration / update request body. One shape for both verbs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterActorRequest {
    /// Local handle, client-validated `[a-z0-9_-]{1,64}` (lowercase
    /// canonical; the bridge rejects any uppercase byte with 422).
    pub handle: String,
    /// RSA `SubjectPublicKeyInfo` DER, base64 on the wire.
    #[serde(with = "b64")]
    pub rsa_spki_der: Vec<u8>,
    /// The signed v2 binding the bridge must verify before serving.
    pub attestation_v2: ActorAttestationV2,
}

/// Success body for both verbs.
#[derive(Clone, Debug, Deserialize)]
pub struct RegisterActorResponse {
    /// Canonical actor URL the directory now serves.
    pub actor_url: String,
}

/// Typed failure surface so the UI can render per-cause copy.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// 403: the handle is operator-reserved (not registered; held back
    /// from self-serve, e.g. for premium release). Reason text attached.
    #[error("handle is reserved: {0}")]
    Reserved(String),
    /// 409: the handle is registered (to this or another agent).
    #[error("handle already registered")]
    HandleTaken,
    /// 422: the bridge rejected the attestation; reason text attached.
    #[error("registry rejected the attestation: {0}")]
    AttestationRejected(String),
    /// 429: per-source rate limit.
    #[error("registry rate limit hit; retry later")]
    RateLimited,
    /// Connection / DNS / TLS / body-read failure.
    #[error("transport: {0}")]
    Transport(String),
    /// Any other non-success status.
    #[error("registry returned HTTP {status}: {body}")]
    Status {
        /// HTTP status code.
        status: u16,
        /// First 256 chars of the response body.
        body: String,
    },
}

/// `POST {base}actors`: first-time registration.
///
/// Path matches the deployed `fetchit-bridge-server`, which serves the
/// whole actor surface (registration, actor docs, `WebFinger`, follow
/// graph) under the unversioned `/actors` family — the edge routes
/// `/actors*` to the bridge.
///
/// # Errors
///
/// A [`RegistryError`] per the contract README's response table.
pub async fn register_actor(
    base: &url::Url,
    req: &RegisterActorRequest,
    http: &reqwest::Client,
) -> Result<RegisterActorResponse, RegistryError> {
    let url = base
        .join("actors")
        .map_err(|e| RegistryError::Transport(format!("build url: {e}")))?;
    let resp = http
        .post(url)
        .json(req)
        .timeout(REGISTRY_TIMEOUT)
        .send()
        .await
        .map_err(|e| RegistryError::Transport(e.to_string()))?;
    decode_response(resp).await
}

/// `PUT {base}actors/<handle>`: update an existing registration
/// (new hint epoch, new profile address, RSA key rotation). The handle
/// in the path comes from `req.handle` and is path-safe by the crate's
/// handle alphabet; the bridge re-validates.
///
/// # Errors
///
/// A [`RegistryError`] per the contract README's response table.
pub async fn update_actor(
    base: &url::Url,
    req: &RegisterActorRequest,
    http: &reqwest::Client,
) -> Result<RegisterActorResponse, RegistryError> {
    let url = base
        .join(&format!("actors/{}", req.handle))
        .map_err(|e| RegistryError::Transport(format!("build url: {e}")))?;
    let resp = http
        .put(url)
        .json(req)
        .timeout(REGISTRY_TIMEOUT)
        .send()
        .await
        .map_err(|e| RegistryError::Transport(e.to_string()))?;
    decode_response(resp).await
}

/// `POST {base}actors` with the actor's own JSON-LD document — the shape the
/// deployed `fetchit-bridge-server` stores and serves. The bridge parses the
/// body with the same [`crate::actor::Actor::from_json_ld`] this crate emits
/// via [`crate::actor::Actor::to_json_ld`], verifies the embedded ML-DSA
/// attestation, and returns a plain-text `registered`/`updated` (so this does
/// NOT decode a JSON body). Registration is idempotent: re-POSTing our own
/// actor returns `200`; a `409` means a DIFFERENT identity holds the handle.
///
/// # Errors
///
/// A [`RegistryError`] carrying the bridge's status + reason.
pub async fn register_actor_doc(
    base: &url::Url,
    doc: &serde_json::Value,
    http: &reqwest::Client,
) -> Result<(), RegistryError> {
    let url = base
        .join("actors")
        .map_err(|e| RegistryError::Transport(format!("build url: {e}")))?;
    let resp = http
        .post(url)
        .json(doc)
        .timeout(REGISTRY_TIMEOUT)
        .send()
        .await
        .map_err(|e| RegistryError::Transport(e.to_string()))?;
    let status = resp.status().as_u16();
    match status {
        200 | 201 => Ok(()),
        409 => Err(RegistryError::HandleTaken),
        429 => Err(RegistryError::RateLimited),
        _ => {
            let body = resp.text().await.unwrap_or_default();
            Err(RegistryError::Status {
                status,
                body: body.chars().take(256).collect(),
            })
        }
    }
}

async fn decode_response(resp: reqwest::Response) -> Result<RegisterActorResponse, RegistryError> {
    let status = resp.status().as_u16();
    match status {
        200 | 201 => resp
            .json()
            .await
            .map_err(|e| RegistryError::Transport(format!("response decode: {e}"))),
        403 => {
            let body = resp.text().await.unwrap_or_default();
            Err(RegistryError::Reserved(body.chars().take(256).collect()))
        }
        409 => Err(RegistryError::HandleTaken),
        422 => {
            let body = resp.text().await.unwrap_or_default();
            Err(RegistryError::AttestationRejected(
                body.chars().take(256).collect(),
            ))
        }
        429 => Err(RegistryError::RateLimited),
        _ => {
            let body = resp.text().await.unwrap_or_default();
            Err(RegistryError::Status {
                status,
                body: body.chars().take(256).collect(),
            })
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn contract_request() -> RegisterActorRequest {
        RegisterActorRequest {
            handle: "josh".into(),
            rsa_spki_der: vec![0xDE, 0xAD, 0xBE, 0xEF],
            attestation_v2: ActorAttestationV2 {
                version: 2,
                profile_addr: "a".repeat(64),
                relay_hint: "https://relay.example:8088/".into(),
                hint_epoch_ms: 1_750_000_000_000,
                ml_dsa_pubkey: vec![0x42; 4],
                signature: vec![0x41; 4],
            },
        }
    }

    #[test]
    fn register_request_matches_contract_fixture() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/registry-v1/register-request.json"
        ))
        .unwrap();
        assert_eq!(serde_json::to_value(contract_request()).unwrap(), fixture);
    }

    #[test]
    fn register_request_round_trips_through_json() {
        let req = contract_request();
        let json = serde_json::to_string(&req).unwrap();
        let back: RegisterActorRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, req);
    }

    #[tokio::test]
    async fn register_posts_to_actors_and_decodes_created() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/actors"))
            .and(body_json(serde_json::to_value(contract_request()).unwrap()))
            .respond_with(ResponseTemplate::new(201).set_body_string(include_str!(
                "../tests/fixtures/registry-v1/register-response.json"
            )))
            .mount(&server)
            .await;
        let base: url::Url = server.uri().parse().unwrap();
        let resp = register_actor(&base, &contract_request(), &reqwest::Client::new())
            .await
            .unwrap();
        assert_eq!(resp.actor_url, "https://etchit.io/actors/josh");
    }

    #[tokio::test]
    async fn update_puts_to_handle_path() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/actors/josh"))
            .respond_with(ResponseTemplate::new(200).set_body_string(include_str!(
                "../tests/fixtures/registry-v1/register-response.json"
            )))
            .mount(&server)
            .await;
        let base: url::Url = server.uri().parse().unwrap();
        update_actor(&base, &contract_request(), &reqwest::Client::new())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn status_codes_map_to_typed_errors() {
        for (status, expect) in [
            (403_u16, "reserved"),
            (409, "taken"),
            (429, "rate"),
            (500, "status"),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/actors"))
                .respond_with(ResponseTemplate::new(status))
                .mount(&server)
                .await;
            let base: url::Url = server.uri().parse().unwrap();
            let err = register_actor(&base, &contract_request(), &reqwest::Client::new())
                .await
                .unwrap_err();
            match expect {
                "reserved" => {
                    assert!(matches!(err, RegistryError::Reserved(_)), "got {err:?}");
                }
                "taken" => assert!(matches!(err, RegistryError::HandleTaken), "got {err:?}"),
                "rate" => assert!(matches!(err, RegistryError::RateLimited), "got {err:?}"),
                _ => assert!(
                    matches!(err, RegistryError::Status { status: 500, .. }),
                    "got {err:?}"
                ),
            }
        }
    }

    #[tokio::test]
    async fn unprocessable_carries_reason_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/actors"))
            .respond_with(ResponseTemplate::new(422).set_body_string("bad attestation"))
            .mount(&server)
            .await;
        let base: url::Url = server.uri().parse().unwrap();
        let err = register_actor(&base, &contract_request(), &reqwest::Client::new())
            .await
            .unwrap_err();
        assert!(
            matches!(err, RegistryError::AttestationRejected(ref r) if r == "bad attestation"),
            "got {err:?}"
        );
    }

    /// Real RSA-2048 `SubjectPublicKeyInfo` DER (base64) baked into the
    /// valid-attestation fixture so the vector is SO-4-ready: a bridge
    /// that parse-validates the SPKI at registration still accepts it.
    const VALID_FIXTURE_SPKI_B64: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2JKTbZExlhDk7PvHi2pS9JgSVR/lUpONW/75Rfc23sI82tfXlqBrMrWOWBOZGrzUm1iQsEnsQlMBF4jZ7ZXCkGFle2mlmC269ObIPb+sIdPMSXbCU8zSNy5WUmFe1YOmydOp83aiDTmJAZJCHVawiXKd6mO3MHN+tU5tI6/x9nB5kKVXqcT+6BzHAvQrbvzqIG2HCPx09HEO79i3hsp29Vwal6h6D7TuD1lf3FQ0YWDuQnXSK59PoJ4Ck4SRTRdGSBIaSYTCmF0Kv31b1Ia86nn8Hi7nXsD6fTfh2OHKuio9g9Dt8TP2tyRdIZ/56sPepir5s03Jx3ug9kuAdhTcHwIDAQAB";

    /// Canonical `actor_url` the bridge constructs from `(domain, handle)`
    /// = `https://etchit.io/actors/josh`, rendered via `url::Url::as_str`.
    /// This is the one byte-sensitive string fed to `verify_binding_v2`;
    /// see the fixtures README's canonical-`actor_url` section.
    fn fixture_actor_url() -> url::Url {
        "https://etchit.io/actors/josh".parse().unwrap()
    }

    /// Build a cryptographically valid `RegisterActorRequest`: a fresh
    /// ML-DSA-65 keypair signs `signing_input_v2` over the canonical
    /// actor fields, so `verify_binding_v2` accepts it. Returns the
    /// request plus the derived agent id hex.
    fn build_valid_request() -> (RegisterActorRequest, String) {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};
        let spki = STANDARD.decode(VALID_FIXTURE_SPKI_B64).unwrap();
        let actor_url = fixture_actor_url();
        let profile_addr = "a".repeat(64);
        let relay_hint = "https://relay.example:8088/";
        let epoch = 1_750_000_000_000u64;
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let pk_bytes = pk.to_bytes();
        let derived = hex::encode(fetchit_relay_proto::derive_agent_id(&pk_bytes));
        let input = crate::attestation::signing_input_v2(
            "josh",
            &actor_url,
            &derived,
            &spki,
            &profile_addr,
            relay_hint,
            epoch,
        )
        .unwrap();
        let sig = dsa
            .sign(&sk, &fetchit_relay_proto::agent_sign_input(&input))
            .unwrap()
            .to_bytes();
        let req = RegisterActorRequest {
            handle: "josh".into(),
            rsa_spki_der: spki,
            attestation_v2: ActorAttestationV2 {
                version: 2,
                profile_addr,
                relay_hint: relay_hint.into(),
                hint_epoch_ms: epoch,
                ml_dsa_pubkey: pk_bytes,
                signature: sig,
            },
        };
        (req, derived)
    }

    /// Regenerator for `register-request-valid.json`. Ignored by default
    /// because each run mints a fresh keypair (nondeterministic bytes).
    /// To refresh the committed fixture after a wire change, run
    /// `cargo test -p fetchit-fedi emit_valid_registration_fixture -- --ignored --nocapture`
    /// and overwrite the file with the printed JSON.
    #[test]
    #[ignore = "regenerator: prints the valid fixture JSON for manual capture"]
    fn emit_valid_registration_fixture() {
        let (req, _derived) = build_valid_request();
        println!("{}", serde_json::to_string_pretty(&req).unwrap());
    }

    #[test]
    fn build_valid_request_is_accepted_by_verify() {
        let (req, derived) = build_valid_request();
        let got = crate::attestation::verify_binding_v2(
            &req.handle,
            &fixture_actor_url(),
            &req.rsa_spki_der,
            &req.attestation_v2,
        )
        .expect("freshly built request must verify");
        assert_eq!(got, derived);
    }

    /// Rot guard + the SO-2 green vector: the COMMITTED valid fixture
    /// must verify under `verify_binding_v2` against the canonical
    /// `actor_url`. If `signing_input_v2` or the wire shape ever drifts,
    /// this fails loudly and the regenerator above refreshes it. Bob's
    /// bridge endpoint test `include_str!`s the same file for its
    /// register -> 201 success path.
    #[test]
    fn committed_valid_fixture_verifies() {
        let req: RegisterActorRequest = serde_json::from_str(include_str!(
            "../tests/fixtures/registry-v1/register-request-valid.json"
        ))
        .expect("valid fixture parses");
        assert_eq!(req.handle, "josh");
        let derived = crate::attestation::verify_binding_v2(
            &req.handle,
            &fixture_actor_url(),
            &req.rsa_spki_der,
            &req.attestation_v2,
        )
        .expect("committed valid fixture must verify against the canonical actor_url");
        assert_eq!(derived.len(), 64);
        assert!(derived
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    }
}
