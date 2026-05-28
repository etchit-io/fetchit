//! Ensures `TransitEnvelope` v2 carries the epoch field across postcard
//! roundtrips. v2 is the wire shape for sealed chat messages.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fetchit_relay_proto::{
    from_bytes, to_bytes, AgentId, EnvelopeKind, GroupId, MachineId, TransitEnvelope,
};

#[test]
fn envelope_v2_carries_epoch() {
    let env = TransitEnvelope {
        version: 2,
        kind: EnvelopeKind::GroupChat,
        group_id: Some(GroupId::from_bytes([0x11; 32])),
        tenant_id: None,
        sender_agent_id: AgentId::from_bytes([0x22; 32]),
        sender_machine_id: MachineId::from_bytes([0x33; 32]),
        timestamp_ms: 1_700_000_000_000,
        epoch: 7,
        ciphertext: vec![0xab; 32],
        nonce: vec![0xcd; 12],
        kem_ciphertext: vec![0xef; 64],
        sender_signature: vec![0xa5; 32],
    };
    let bytes = to_bytes(&env).unwrap();
    let decoded: TransitEnvelope = from_bytes(&bytes).unwrap();
    assert_eq!(decoded.version, 2);
    assert_eq!(decoded.epoch, 7);
    assert_eq!(decoded, env);
}
