//! Integration coverage for [`RelaySet`] against in-process
//! relay-server harnesses. Proves the M3 fan-out contract end-to-end:
//! one `send` lands on every healthy relay, and partial failure
//! degrades gracefully without dropping the whole send.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fetchit_relay_client::{Client, ClientConfig, RelaySet, Signer, StaticKeySigner};
use fetchit_relay_proto::{
    AgentId, DedupeKey, EnvelopeKind, MachineId, Region, TransitEnvelope, WIRE_VERSION,
};
use fetchit_relay_server::{AcceptAllVerifier, Server, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use url::Url;

async fn start_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = ServerConfig::defaults(addr, Region::Nyc);
    let server = Server::new(cfg).with_verifier(Arc::new(AcceptAllVerifier));
    let (router, _state) = server.router();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    addr
}

fn envelope_from(sender: AgentId, body: &[u8]) -> TransitEnvelope {
    TransitEnvelope {
        version: WIRE_VERSION,
        kind: EnvelopeKind::Dm,
        group_id: None,
        tenant_id: None,
        sender_agent_id: sender,
        sender_machine_id: MachineId::from_bytes([0u8; 32]),
        timestamp_ms: 1,
        epoch: 0,
        ciphertext: body.to_vec(),
        nonce: vec![0u8; 12],
        kem_ciphertext: vec![0u8; 32],
        sender_signature: vec![0u8; 32],
    }
}

/// Two independent relays receive the same envelope from a single
/// `RelaySet::send`. The receiver, connected only to relay B, must
/// see the delivery — proves relay B accepted. The `SendOutcome.extras`
/// vec carries the receipt for relay A — proves relay A accepted too.
#[tokio::test]
async fn send_fans_out_to_every_relay_in_set() {
    let addr_a = start_server().await;
    let addr_b = start_server().await;
    let base_a = Url::parse(&format!("http://{addr_a}/")).unwrap();
    let base_b = Url::parse(&format!("http://{addr_b}/")).unwrap();

    let alice_signer: Arc<dyn Signer + Send + Sync> = Arc::new(StaticKeySigner::from_public_key(
        b"alice-public-key".to_vec(),
    ));
    let bob_signer: Arc<dyn Signer + Send + Sync> =
        Arc::new(StaticKeySigner::from_public_key(b"bob-public-key".to_vec()));
    let alice_id = AgentId::from_bytes(alice_signer.agent_id());
    let bob_id = AgentId::from_bytes(bob_signer.agent_id());

    // Alice spans both relays. Bob listens only on relay B.
    let alice_set = RelaySet::connect(
        vec![ClientConfig::new(base_a), ClientConfig::new(base_b.clone())],
        alice_signer,
    )
    .await
    .unwrap();
    let bob = Client::connect(ClientConfig::new(base_b), bob_signer)
        .await
        .unwrap();

    let payload = b"hello from alice's relay set";
    let outcome = alice_set
        .send(
            bob_id,
            envelope_from(alice_id, payload),
            DedupeKey::from_bytes([0x11; 16]),
        )
        .await
        .unwrap();
    // Primary is the first relay's receipt; the other relay's receipt
    // sits in extras. Both must be acked.
    assert!(outcome.primary.accepted_at_ms > 0, "primary receipt valid");
    assert_eq!(outcome.extras.len(), 1, "exactly one extra relay receipt");
    let extra = outcome.extras.into_iter().next().unwrap().unwrap();
    assert!(extra.accepted_at_ms > 0, "second relay also accepted");

    // Bob (relay B only) sees the delivery — proves relay B accepted
    // and routed end-to-end.
    let delivery = tokio::time::timeout(Duration::from_secs(2), bob.next_delivery())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(delivery.envelope.ciphertext, payload);
    assert_eq!(delivery.envelope.sender_agent_id, alice_id);
}

/// One healthy relay plus one URL that never completes its handshake
/// (random unbound localhost port). `connect` must succeed because at
/// least one relay handshakes. A subsequent `send` only reaches the
/// healthy one but still resolves Ok.
#[tokio::test]
async fn connect_partial_success_keeps_healthy_relay_alive() {
    let addr_ok = start_server().await;
    let base_ok = Url::parse(&format!("http://{addr_ok}/")).unwrap();
    // Bind+drop a listener to get a port that is unbound for the
    // RelaySet::connect attempt — handshake against it will fail.
    let dead_addr = {
        let lis = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = lis.local_addr().unwrap();
        drop(lis);
        a
    };
    let base_dead = Url::parse(&format!("http://{dead_addr}/")).unwrap();

    let alice_signer: Arc<dyn Signer + Send + Sync> = Arc::new(StaticKeySigner::from_public_key(
        b"alice-public-key".to_vec(),
    ));
    let bob_signer: Arc<dyn Signer + Send + Sync> =
        Arc::new(StaticKeySigner::from_public_key(b"bob-public-key".to_vec()));
    let alice_id = AgentId::from_bytes(alice_signer.agent_id());
    let bob_id = AgentId::from_bytes(bob_signer.agent_id());

    let alice_set = RelaySet::connect(
        vec![
            ClientConfig::new(base_ok.clone()),
            ClientConfig::new(base_dead),
        ],
        alice_signer,
    )
    .await
    .expect("at least one healthy relay → Ok");

    let bob = Client::connect(ClientConfig::new(base_ok), bob_signer)
        .await
        .unwrap();

    let payload = b"survives one dead relay";
    let outcome = alice_set
        .send(
            bob_id,
            envelope_from(alice_id, payload),
            DedupeKey::from_bytes([0x22; 16]),
        )
        .await
        .unwrap();
    assert!(outcome.primary.accepted_at_ms > 0);
    // The dead URL never made it past handshake, so the set holds
    // only one relay. No extras.
    assert!(
        outcome.extras.is_empty(),
        "only the healthy relay is in the set",
    );

    let delivery = tokio::time::timeout(Duration::from_secs(2), bob.next_delivery())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(delivery.envelope.ciphertext, payload);
}

/// `next_delivery` drains the merged inbox: Bob sees both Alice's
/// send (via relay A) and Carol's send (via relay B), in arrival
/// order. The chat-layer dedupe key is the envelope `message_id`;
/// at the relay layer fan-in is unordered concatenation.
#[tokio::test]
async fn next_delivery_merges_inboxes_across_relays() {
    let addr_a = start_server().await;
    let addr_b = start_server().await;
    let base_a = Url::parse(&format!("http://{addr_a}/")).unwrap();
    let base_b = Url::parse(&format!("http://{addr_b}/")).unwrap();

    let alice_signer: Arc<dyn Signer + Send + Sync> = Arc::new(StaticKeySigner::from_public_key(
        b"alice-public-key".to_vec(),
    ));
    let carol_signer: Arc<dyn Signer + Send + Sync> = Arc::new(StaticKeySigner::from_public_key(
        b"carol-public-key".to_vec(),
    ));
    let bob_signer: Arc<dyn Signer + Send + Sync> =
        Arc::new(StaticKeySigner::from_public_key(b"bob-public-key".to_vec()));
    let alice_id = AgentId::from_bytes(alice_signer.agent_id());
    let carol_id = AgentId::from_bytes(carol_signer.agent_id());
    let bob_id = AgentId::from_bytes(bob_signer.agent_id());

    // Alice on relay A only, Carol on relay B only. Bob spans both
    // via a RelaySet — his next_delivery merges both relays' inboxes.
    let alice = Client::connect(ClientConfig::new(base_a.clone()), alice_signer)
        .await
        .unwrap();
    let carol = Client::connect(ClientConfig::new(base_b.clone()), carol_signer)
        .await
        .unwrap();
    let bob_set = RelaySet::connect(
        vec![ClientConfig::new(base_a), ClientConfig::new(base_b)],
        bob_signer,
    )
    .await
    .unwrap();

    alice
        .send(
            bob_id,
            envelope_from(alice_id, b"from alice via A"),
            DedupeKey::from_bytes([0x33; 16]),
        )
        .await
        .unwrap();
    carol
        .send(
            bob_id,
            envelope_from(carol_id, b"from carol via B"),
            DedupeKey::from_bytes([0x44; 16]),
        )
        .await
        .unwrap();

    let mut seen_senders: Vec<AgentId> = Vec::new();
    for _ in 0..2 {
        let d = tokio::time::timeout(Duration::from_secs(2), bob_set.next_delivery())
            .await
            .unwrap()
            .unwrap();
        seen_senders.push(d.envelope.sender_agent_id);
    }
    assert!(seen_senders.contains(&alice_id), "alice delivered via A");
    assert!(seen_senders.contains(&carol_id), "carol delivered via B");
}
