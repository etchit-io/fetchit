//! Hermetic proof for the daemonless identity-unification fix.
//!
//! In the daemonless profile the chat client's agent identity is the local
//! `LocalSignerVault` ML-DSA-65 key (agent id `V`), while the embedded x0xd
//! mints its own. For engine-A group join to resolve the owner's pair-record,
//! the embedded x0xd must ADOPT the vault key so the phone is ONE agent. That
//! only works if x0x derives the SAME agent id from the vault's key bytes that
//! the chat/relay layer does -- and two saorsa-pqc versions are linked here
//! (0.4.2 via fetchit-relay-client, 0.5.1 via x0x), so the cross-version
//! `from_bytes` round-trip + derivation must be byte-for-byte equal. If this
//! ever regresses, the daemonless group-owner pair-record lands under the
//! wrong key and joiners 404.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use fetchit_relay_client::{MlDsaSigner, Signer};

#[test]
fn vault_ml_dsa_key_yields_same_agent_id_in_x0x() {
    let signer = MlDsaSigner::generate().expect("vault keygen");
    let pk = signer.public_key();
    let sk = signer.secret_key_bytes();
    let v = hex::encode(signer.agent_id());

    let kp = x0x::identity::AgentKeypair::from_bytes(&pk, &sk)
        .expect("x0x AgentKeypair::from_bytes(vault pk/sk) must parse the vault key bytes");
    let x0x_id = hex::encode(kp.agent_id().to_vec());

    assert_eq!(
        v, x0x_id,
        "chat-vault agent id V must equal x0x agent id for the same ML-DSA-65 key"
    );
}
