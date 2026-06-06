//! Inbound handlers for the M2.5 Welcome contingency bridge (#251 Layer 2).
//!
//! Called from the inbound dispatch loop whenever a `TransitEnvelope` carries
//! `EnvelopeKind::WelcomeBlobRequest` (owner-side) or
//! `EnvelopeKind::WelcomeBlobResponse` (joiner-side).
//!
//! Owner-side: unseal the request, fetch the pending Welcome blob from local
//! x0xd, and reply via `dispatch_welcome_blob_to_joiner`.
//!
//! Joiner-side: unseal the blob, base64-decode the raw bytes, and POST to
//! local x0xd `POST /groups/join` with `treekem_welcome_b64` to complete the
//! MLS group-join.

use base64::Engine as _;
use fetchit_relay_proto::{EnvelopeKind, TransitEnvelope};
use serde::Serialize;

use crate::error::{ChatError, Result};
use crate::groups::welcome_bridge::{unseal_welcome_blob, unseal_welcome_request};
use crate::http::Http;
use crate::local_store::StoreLayout;
use crate::transport::Router;

/// Body sent to x0xd `POST /groups/join` on the joiner-side when delivering
/// a `TreeKEM` Welcome blob received over the bridge. The daemon's inline-Welcome
/// path accepts `treekem_welcome_b64` alongside the usual `invite` field.
/// We omit `invite` because the Welcome blob carries the full MLS state.
#[derive(Serialize)]
struct JoinWithWelcomeRequest<'a> {
    /// Group id the Welcome covers.
    group_id: &'a str,
    /// Base64-encoded raw `TreeKEM` Welcome bytes from the owning daemon.
    treekem_welcome_b64: &'a str,
}

/// Owner-side handler: unseal a `WelcomeBlobRequest`, fetch the pending
/// Welcome blob from local x0xd, and dispatch it back to the joiner.
///
/// # Errors
/// - [`ChatError::Invalid`] when `transit.kind` is wrong, unseal fails,
///   or the joiner agent-id from the payload is malformed.
/// - [`ChatError::Invalid`] with a FIXME note when the owner-side
///   pending-Welcome fetch endpoint is not yet exposed by x0xd.
/// - [`ChatError::ShareCardMissing`] / relay errors from the blob dispatcher.
// The async is intentional: once the owner-side endpoint lands this function
// will await the fetch + dispatch calls. The FIXME body has no awaits yet.
#[allow(clippy::unused_async)]
pub(crate) async fn handle_inbound_welcome_request<S>(
    signer: &S,
    router: &Router,
    layout: &StoreLayout,
    identity_kem_secret: &[u8],
    local_machine_id: [u8; 32],
    transit: &TransitEnvelope,
) -> Result<()>
where
    S: fetchit_relay_client::Signer + ?Sized,
{
    if transit.kind != EnvelopeKind::WelcomeBlobRequest {
        return Err(ChatError::Invalid(format!(
            "handle_inbound_welcome_request called on kind={:?}",
            transit.kind
        )));
    }
    let payload = unseal_welcome_request(
        identity_kem_secret,
        &transit.kem_ciphertext,
        &transit.nonce,
        &transit.ciphertext,
    )?;

    let joiner_bytes = hex::decode(&payload.joiner_agent_id).map_err(|e| {
        ChatError::Invalid(format!("welcome-request joiner_agent_id hex decode: {e}"))
    })?;
    if joiner_bytes.len() != 32 {
        return Err(ChatError::Invalid(format!(
            "welcome-request joiner_agent_id wrong length: {}",
            joiner_bytes.len()
        )));
    }
    let mut joiner_arr = [0u8; 32];
    joiner_arr.copy_from_slice(&joiner_bytes);

    // FIXME(#251-B5-followup): wire owner-side pending-welcome fetch when
    // x0xd exposes the endpoint. No public REST endpoint for fetching a
    // pending Welcome blob for a specific joiner exists in x0xd-client as of
    // v1.0. When upstream lands the endpoint, replace this error with a call
    // to fetch the blob and pass the bytes to dispatch_welcome_blob_to_joiner.
    let _ = (
        signer,
        router,
        layout,
        local_machine_id,
        joiner_arr,
        payload,
    );
    Err(ChatError::Invalid(
        "welcome-bridge owner-side fetch unimplemented: \
         waiting for x0xd to expose pending-welcome endpoint (#251-B5-followup)"
            .into(),
    ))
}

/// Joiner-side handler: unseal a `WelcomeBlobResponse`, decode the Welcome
/// bytes, and POST to local x0xd `POST /groups/join` to complete the MLS
/// group-join.
///
/// # Errors
/// - [`ChatError::Invalid`] when `transit.kind` is wrong, unseal fails,
///   base64-decode of the blob fails, or the x0xd join POST fails.
pub(crate) async fn handle_inbound_welcome_response(
    identity_kem_secret: &[u8],
    http: &Http,
    transit: &TransitEnvelope,
) -> Result<()> {
    if transit.kind != EnvelopeKind::WelcomeBlobResponse {
        return Err(ChatError::Invalid(format!(
            "handle_inbound_welcome_response called on kind={:?}",
            transit.kind
        )));
    }
    let payload = unseal_welcome_blob(
        identity_kem_secret,
        &transit.kem_ciphertext,
        &transit.nonce,
        &transit.ciphertext,
    )?;

    // Validate the blob b64 decodes cleanly before posting.
    base64::engine::general_purpose::STANDARD
        .decode(payload.blob_b64.as_bytes())
        .map_err(|e| ChatError::Invalid(format!("welcome-blob b64 decode: {e}")))?;

    let req = JoinWithWelcomeRequest {
        group_id: &payload.group_id,
        treekem_welcome_b64: &payload.blob_b64,
    };
    // The daemon's MemberAdded Welcome path accepts treekem_welcome_b64 on
    // POST /groups/join (saorsa-labs/x0x src/bin/x0xd.rs:7960-7990 @ 91951a5).
    let _: serde_json::Value = http.post_json("/groups/join", &req).await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::chat_crypto::kem_keygen;
    use crate::groups::welcome_bridge::{
        seal_welcome_blob, seal_welcome_request, WelcomeBlobPayload, WelcomeRequestPayload,
    };
    use base64::engine::general_purpose::STANDARD as B64;
    use fetchit_relay_proto::{AgentId as RelayAgentId, MachineId, WIRE_VERSION};
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    struct StubSigner;

    #[async_trait::async_trait]
    impl fetchit_relay_client::Signer for StubSigner {
        fn agent_id(&self) -> [u8; 32] {
            [0u8; 32]
        }
        fn public_key(&self) -> Vec<u8> {
            vec![0u8; 32]
        }
        async fn sign(&self, _message: &[u8]) -> std::result::Result<Vec<u8>, String> {
            Ok(vec![0u8; 64])
        }
    }

    fn make_request_transit(owner_kem_pub: &[u8]) -> TransitEnvelope {
        let payload = WelcomeRequestPayload {
            group_id: "a".repeat(64),
            joiner_agent_id: hex::encode([0xbbu8; 32]),
            ts_ms: 1_000,
        };
        let parts = seal_welcome_request(owner_kem_pub, &payload).unwrap();
        TransitEnvelope {
            version: WIRE_VERSION,
            kind: EnvelopeKind::WelcomeBlobRequest,
            group_id: None,
            tenant_id: None,
            sender_agent_id: RelayAgentId::from_bytes([0xaau8; 32]),
            sender_machine_id: MachineId::from_bytes([0x01u8; 32]),
            timestamp_ms: 1_000,
            epoch: 0,
            ciphertext: parts.ciphertext,
            nonce: parts.nonce,
            kem_ciphertext: parts.kem_ciphertext,
            sender_signature: vec![0u8; 64],
        }
    }

    fn make_response_transit(
        joiner_kem_pub: &[u8],
        group_id: &str,
        blob_b64: &str,
    ) -> TransitEnvelope {
        let payload = WelcomeBlobPayload {
            group_id: group_id.to_owned(),
            blob_b64: blob_b64.to_owned(),
            ts_ms: 2_000,
        };
        let parts = seal_welcome_blob(joiner_kem_pub, &payload).unwrap();
        TransitEnvelope {
            version: WIRE_VERSION,
            kind: EnvelopeKind::WelcomeBlobResponse,
            group_id: None,
            tenant_id: None,
            sender_agent_id: RelayAgentId::from_bytes([0xaau8; 32]),
            sender_machine_id: MachineId::from_bytes([0x01u8; 32]),
            timestamp_ms: 2_000,
            epoch: 0,
            ciphertext: parts.ciphertext,
            nonce: parts.nonce,
            kem_ciphertext: parts.kem_ciphertext,
            sender_signature: vec![0u8; 64],
        }
    }

    /// Owner-side: `WelcomeBlobRequest` arrival returns the FIXME error
    /// cleanly. When x0xd exposes the pending-welcome endpoint this test
    /// will be updated to assert a queued `WelcomeBlobResponse` instead.
    #[tokio::test]
    async fn inbound_welcome_blob_request_owner_side_returns_fixme_error() {
        let dir = tempfile::tempdir().unwrap();
        let layout = crate::local_store::StoreLayout::ensure(dir.path().to_path_buf()).unwrap();

        let (pk_owner, sk_owner) = kem_keygen().unwrap();

        let router = crate::transport::Router::new();
        let transit = make_request_transit(&pk_owner);

        let err = handle_inbound_welcome_request(
            &StubSigner,
            &router,
            &layout,
            &sk_owner,
            [0x01u8; 32],
            &transit,
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, ChatError::Invalid(ref msg) if msg.contains("owner-side fetch unimplemented")),
            "expected FIXME error, got {err:?}",
        );
    }

    /// Joiner-side: `WelcomeBlobResponse` arrival with a 33 KiB blob results
    /// in a single POST to `/groups/join` carrying the `group_id` and the
    /// `treekem_welcome_b64`.
    #[tokio::test]
    async fn inbound_welcome_blob_response_joiner_side_posts_to_local_x0xd() {
        let server = MockServer::start().await;

        let group_id = "b".repeat(64);
        let blob_bytes = vec![0xCDu8; 33 * 1024];
        let blob_b64 = B64.encode(&blob_bytes);

        Mock::given(method("POST"))
            .and(path("/groups/join"))
            .and(body_partial_json(serde_json::json!({
                "group_id": &group_id,
                "treekem_welcome_b64": &blob_b64,
            })))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"ok": true, "group_id": &group_id})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let (pk_joiner, sk_joiner) = kem_keygen().unwrap();
        let transit = make_response_transit(&pk_joiner, &group_id, &blob_b64);

        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        handle_inbound_welcome_response(&sk_joiner, &http, &transit)
            .await
            .unwrap();
    }
}
