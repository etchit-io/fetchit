//! Live `x0xd` integration smoke. Ignored by default — run explicitly:
//!
//! ```text
//! FETCHIT_X0XD_LIVE_BASE=http://127.0.0.1:6464 \
//! FETCHIT_X0XD_LIVE_TOKEN=$(cat ~/.local/share/x0x/api-token) \
//!     cargo test -p fetchit-relay-client --test live_x0xd -- --ignored --nocapture
//! ```
//!
//! Exists to catch drift between our mock x0xd (used in the regular CI
//! tests) and the real daemon's wire shape. Run before every release
//! and whenever the `X0xdSigner` code or x0xd's `/agent/sign` schema
//! changes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fetchit_relay_client::{Signer, X0xdSigner};
use fetchit_relay_proto::derive_agent_id;
use saorsa_pqc::api::sig::{MlDsa, MlDsaPublicKey, MlDsaSignature, MlDsaVariant};
use url::Url;

fn live_env() -> Option<(Url, String)> {
    let base = std::env::var("FETCHIT_X0XD_LIVE_BASE").ok()?;
    let token = std::env::var("FETCHIT_X0XD_LIVE_TOKEN").ok()?;
    let url = Url::parse(&base).expect("FETCHIT_X0XD_LIVE_BASE must be a valid URL");
    Some((url, token))
}

#[tokio::test]
#[ignore = "requires a running x0xd; set FETCHIT_X0XD_LIVE_BASE + FETCHIT_X0XD_LIVE_TOKEN"]
async fn x0xd_signer_round_trip_against_real_daemon() {
    let Some((base, token)) = live_env() else {
        panic!(
            "FETCHIT_X0XD_LIVE_BASE and FETCHIT_X0XD_LIVE_TOKEN must both be set for --ignored runs",
        );
    };

    eprintln!("[live] connecting to {base}");
    let signer = X0xdSigner::connect(base.clone(), token.clone())
        .await
        .expect("X0xdSigner::connect must succeed against a real x0xd");

    let agent_id = signer.agent_id();
    let public_key = signer.public_key();
    eprintln!(
        "[live] agent_id={} public_key_len={}",
        hex::encode(agent_id),
        public_key.len()
    );

    // 1. The agent id the signer reports must be derived from the public
    //    key using the shared convention. Catches mock drift in agent_id
    //    encoding.
    let derived = derive_agent_id(&public_key);
    assert_eq!(
        derived, agent_id,
        "agent_id reported by x0xd must equal derive_agent_id(public_key)"
    );

    // 2. The agent id must match what `GET /agent` reports independently.
    //    Catches mock drift in the agent endpoint or hash convention.
    let http = reqwest::Client::new();
    let agent_resp: serde_json::Value = http
        .get(base.join("agent").unwrap())
        .bearer_auth(&token)
        .send()
        .await
        .expect("GET /agent must succeed")
        .error_for_status()
        .expect("GET /agent must return 2xx")
        .json()
        .await
        .expect("GET /agent must return JSON");
    let reported_agent_id_hex = agent_resp
        .pointer("/data/agent_id")
        .or_else(|| agent_resp.get("agent_id"))
        .and_then(|v| v.as_str())
        .expect("GET /agent must include agent_id");
    assert_eq!(
        reported_agent_id_hex,
        hex::encode(agent_id),
        "GET /agent's agent_id must match X0xdSigner's",
    );

    // 3. A signature produced by the signer must verify against the
    //    cached public key using saorsa-pqc directly. Catches drift in
    //    the `/agent/sign` response shape, algorithm tag, or signing
    //    semantics.
    let payload = b"fetchit-relay/live-test/v1\0probe-bytes";
    let sig_bytes = signer
        .sign(payload)
        .await
        .expect("signer.sign must succeed");
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let pk = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &public_key)
        .expect("public_key parse must succeed");
    let sig = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &sig_bytes)
        .expect("signature parse must succeed");
    assert!(
        dsa.verify(&pk, payload, &sig)
            .expect("dsa.verify must succeed"),
        "x0xd-produced signature must verify against its own public key"
    );

    eprintln!("[live] all assertions passed against real x0xd");
}
