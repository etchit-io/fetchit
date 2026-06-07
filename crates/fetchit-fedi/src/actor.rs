//! Actor identity + Mastodon-compatible JSON-LD representation.
//!
//! Per plan decision [III] and the cross-crate cut documented in
//! `docs/superpowers/plans/2026-06-07-m4-fediverse-impl-plan.md` Stage 1,
//! `ActorIdentity` is **pure data**. The factory (RSA-2048 generation,
//! ML-DSA-65 attestation signing, [`StoreLayout`] I/O) lives in
//! `fetchit-chat::Client::mint_actor_identity` so the dep direction
//! stays unidirectional (`chat → fedi`).

use crate::attestation::MlDsaAttestation;

/// A fetchit-issued fediverse actor: a stable identity bound to a chat
/// `agent_id_hex`, signed under the chat-identity ML-DSA-65 key.
///
/// Construction goes through [`Self::new`] (fresh mint) or
/// [`Self::from_persisted`] (reload from disk). Both are pure-data
/// constructors; neither touches the network or the filesystem.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorIdentity {
    /// Local-part of the handle (e.g. `"josh"` for `@josh@etchit.io`).
    pub handle: String,
    /// Canonical actor URL (e.g. `https://etchit.io/actors/josh`).
    pub actor_url: url::Url,
    /// 64-hex chat agent id this actor is bound to.
    pub agent_id_hex: String,
    /// RSA-2048 private key in PEM form. Used by the HTTP Signature
    /// signer when delivering outbound POSTs.
    pub rsa_priv_pem: String,
    /// ML-DSA-65 attestation binding the RSA public key (derivable from
    /// `rsa_priv_pem`) to the chat-identity ML-DSA key.
    pub ml_dsa_attestation: MlDsaAttestation,
}

impl ActorIdentity {
    /// Pure-data constructor used by `fetchit_chat::Client::mint_actor_identity`
    /// after it has generated the RSA key and signed the attestation.
    #[must_use]
    pub fn new(
        handle: String,
        actor_url: url::Url,
        agent_id_hex: String,
        rsa_priv_pem: String,
        ml_dsa_attestation: MlDsaAttestation,
    ) -> Self {
        Self {
            handle,
            actor_url,
            agent_id_hex,
            rsa_priv_pem,
            ml_dsa_attestation,
        }
    }

    /// Symmetric reload after `fetchit_chat::Client::load_actor_identity`
    /// has read the persisted bytes. Field order intentionally mirrors
    /// the on-disk layout for grep-clarity in the chat-side loader.
    #[must_use]
    pub fn from_persisted(
        handle: String,
        rsa_priv_pem: String,
        ml_dsa_attestation: MlDsaAttestation,
        actor_url: url::Url,
        agent_id_hex: String,
    ) -> Self {
        Self {
            handle,
            actor_url,
            agent_id_hex,
            rsa_priv_pem,
            ml_dsa_attestation,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn sample_attestation() -> MlDsaAttestation {
        MlDsaAttestation::new(vec![0x11; 8], vec![0x22; 8])
    }

    #[test]
    fn new_round_trips_fields() {
        let att = sample_attestation();
        let id = ActorIdentity::new(
            "josh".into(),
            "https://etchit.io/actors/josh".parse().unwrap(),
            "deadbeef".into(),
            "-----BEGIN RSA PRIVATE KEY-----\n...".into(),
            att.clone(),
        );

        assert_eq!(id.handle, "josh");
        assert_eq!(id.actor_url.as_str(), "https://etchit.io/actors/josh");
        assert_eq!(id.agent_id_hex, "deadbeef");
        assert!(id.rsa_priv_pem.starts_with("-----BEGIN RSA"));
        assert_eq!(id.ml_dsa_attestation, att);
    }

    #[test]
    fn from_persisted_yields_identical_struct_as_new() {
        let att = sample_attestation();
        let actor_url: url::Url = "https://etchit.io/actors/josh".parse().unwrap();

        let minted = ActorIdentity::new(
            "josh".into(),
            actor_url.clone(),
            "deadbeef".into(),
            "PRIV".into(),
            att.clone(),
        );
        let reloaded = ActorIdentity::from_persisted(
            "josh".into(),
            "PRIV".into(),
            att,
            actor_url,
            "deadbeef".into(),
        );

        assert_eq!(minted, reloaded);
    }
}
