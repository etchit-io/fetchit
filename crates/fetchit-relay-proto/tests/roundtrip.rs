//! End-to-end encode/decode coverage spanning the full frame surface.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fetchit_relay_proto::{
    from_bytes, to_bytes, Ack, AgentId, AuthChallenge, AuthVerifyRequest, AuthVerifyResponse, Bye,
    ByeReason, Capability, CapabilityClaims, CapabilityToken, ClientFrame, DedupeKey, Deliver,
    EffectiveCapabilities, EnvelopeKind, FeatureFlag, GroupId, Hello, MachineId, Ping, Pong, Ready,
    Region, SendFrame, ServerFrame, Subscribe, TenantId, Throttle, ThrottleReason, TransitEnvelope,
};
use std::collections::BTreeSet;

fn envelope() -> TransitEnvelope {
    TransitEnvelope {
        version: 2,
        kind: EnvelopeKind::GroupChat,
        group_id: Some(GroupId::from_bytes([0x33; 32])),
        tenant_id: Some(TenantId::new("acme")),
        sender_agent_id: AgentId::from_bytes([0x11; 32]),
        sender_machine_id: MachineId::from_bytes([0x22; 32]),
        timestamp_ms: 1_700_000_000_000,
        epoch: 0,
        ciphertext: vec![0xab; 256],
        nonce: vec![0xcd; 12],
        kem_ciphertext: vec![0xef; 1088],
        sender_signature: vec![0xa5; 3293],
    }
}

#[test]
fn client_frame_variants_all_roundtrip() {
    let frames: Vec<ClientFrame> = vec![
        ClientFrame::Hello(Hello {
            client_version: "client/1.0".to_owned(),
            tenant_id: Some(TenantId::new("acme")),
            preferred_region: Some(Region::Fra),
            capabilities: Some(CapabilityToken {
                claims: CapabilityClaims {
                    agent_id: AgentId::from_bytes([0x44; 32]),
                    tenant_id: Some(TenantId::new("acme")),
                    issued_at_ms: 1_700_000_000_000,
                    expires_at_ms: 1_700_003_600_000,
                    capabilities: vec![
                        Capability::MaxGroupSize(50),
                        Capability::AllowedRegions(BTreeSet::from([Region::Fra])),
                        Capability::Feature(FeatureFlag::AuditConsume),
                    ],
                    issuer_key_id: "issuer-v1".to_owned(),
                },
                signature: vec![0x77; 3293],
            }),
        }),
        ClientFrame::Subscribe(Subscribe {
            topic: "inbox".to_owned(),
        }),
        ClientFrame::Send(SendFrame {
            to: AgentId::from_bytes([0x55; 32]),
            envelope: envelope(),
            dedupe_key: DedupeKey::from_bytes([0x66; 16]),
        }),
        ClientFrame::Ping(Ping { nonce: 0x1234 }),
        ClientFrame::Bye(Bye {
            reason: ByeReason::ClientGoodbye,
        }),
    ];

    for f in frames {
        let bytes = to_bytes(&f).unwrap();
        let decoded: ClientFrame = from_bytes(&bytes).unwrap();
        assert_eq!(f, decoded);
    }
}

#[test]
fn server_frame_variants_all_roundtrip() {
    let frames: Vec<ServerFrame> = vec![
        ServerFrame::Ready(Ready {
            server_version: "server/1.0".to_owned(),
            region: Region::Nyc,
            effective_capabilities: EffectiveCapabilities::default_profile(),
        }),
        ServerFrame::Ack(Ack {
            dedupe_key: DedupeKey::from_bytes([0x66; 16]),
            accepted_at_ms: 1_700_000_001_000,
        }),
        ServerFrame::Deliver(Deliver {
            envelope: envelope(),
            transit_seq: 7,
            delivered_at_ms: 1_700_000_002_000,
        }),
        ServerFrame::Throttle(Throttle {
            retry_after_ms: 500,
            reason: ThrottleReason::PerRecipientCapacity,
        }),
        ServerFrame::Pong(Pong { nonce: 0x1234 }),
        ServerFrame::Bye(Bye {
            reason: ByeReason::ServerShutdown,
        }),
    ];

    for f in frames {
        let bytes = to_bytes(&f).unwrap();
        let decoded: ServerFrame = from_bytes(&bytes).unwrap();
        assert_eq!(f, decoded);
    }
}

#[test]
fn auth_handshake_roundtrips() {
    let challenge = AuthChallenge {
        challenge: [0xab; 32],
        expires_at_ms: 1_700_000_005_000,
    };
    let bytes = to_bytes(&challenge).unwrap();
    let decoded: AuthChallenge = from_bytes(&bytes).unwrap();
    assert_eq!(challenge, decoded);

    let req = AuthVerifyRequest {
        agent_id: AgentId::from_bytes([0xcd; 32]),
        agent_public_key: vec![0u8; 1952],
        challenge: [0xab; 32],
        signature: vec![0u8; 3293],
    };
    let bytes = to_bytes(&req).unwrap();
    let decoded: AuthVerifyRequest = from_bytes(&bytes).unwrap();
    assert_eq!(req, decoded);

    let resp = AuthVerifyResponse {
        token: "token-bytes".to_owned(),
        expires_at_ms: 1_700_001_000_000,
    };
    let bytes = to_bytes(&resp).unwrap();
    let decoded: AuthVerifyResponse = from_bytes(&bytes).unwrap();
    assert_eq!(resp, decoded);
}
