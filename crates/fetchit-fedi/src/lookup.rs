//! Tolerant remote-actor lookup (M5.1, Component A).
//!
//! [`RemoteActor`] decodes ANY well-formed `ActivityPub` actor,
//! attestation present or not, so the desktop can render public-only
//! cards for vanilla fediverse accounts. This type is for CLIENT
//! lookup only: relay-side ingest keeps the strict
//! [`crate::actor::Actor`] decode (attestation required), and that
//! boundary is deliberate; widening relay ingest is M5.2 scope.

use crate::actor::{
    fetch_json_ld_at_url, is_actor_class_type, pinned_no_redirect_client, required_str,
    spki_pem_to_der, ActorError, FetchActorError, ACTOR_FETCH_TIMEOUT,
    PQ_ATTESTATION_V2_PROPERTY_URI,
};
use crate::attestation::ActorAttestationV2;
use serde_json::Value;

/// A remote actor as seen by the lookup path. Every field beyond the
/// identity pair is optional; trust is established exclusively by
/// [`RemoteActor::verify_attestation_v2`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteActor {
    /// Canonical actor URL (`id`).
    pub id: url::Url,
    /// `inbox` endpoint — where Follow/Create/DM activities are posted.
    /// Mandatory per `ActivityPub` §4.1; every real actor serves one.
    pub inbox: url::Url,
    /// `preferredUsername` as served; the local part of the handle.
    pub preferred_username: String,
    /// `publicKey.publicKeyPem` when served.
    pub rsa_public_key_pem: Option<String>,
    /// v2 attestation when served. Present-but-malformed is a decode
    /// error, never silently `None`.
    pub attestation_v2: Option<ActorAttestationV2>,
}

impl RemoteActor {
    /// Decode from an actor JSON-LD document, tolerating absent
    /// attestation and public key.
    ///
    /// # Errors
    ///
    /// [`ActorError`] on missing `id`/`preferredUsername`, a non-actor
    /// `type`, a `publicKey.owner` that does not match `id`, or a
    /// malformed v2 attestation value.
    pub fn from_json_ld(value: &Value) -> Result<Self, ActorError> {
        // Same actor-class allowlist as the strict decode: a Note or
        // Activity object styled as an actor is rejected outright.
        if let Some(type_str) = value.get("type").and_then(Value::as_str) {
            if !is_actor_class_type(type_str) {
                return Err(ActorError::InvalidField {
                    name: "type".into(),
                    reason: format!(
                        "expected one of {{Person, Service, Application, Organization, Group}}; got {type_str:?}"
                    ),
                });
            }
        }
        let id_str = required_str(value, "id")?;
        let id: url::Url = id_str.parse().map_err(|e| ActorError::InvalidField {
            name: "id".into(),
            reason: format!("{e}"),
        })?;
        let inbox_str = required_str(value, "inbox")?;
        let inbox: url::Url = inbox_str.parse().map_err(|e| ActorError::InvalidField {
            name: "inbox".into(),
            reason: format!("{e}"),
        })?;
        let preferred_username = required_str(value, "preferredUsername")?.to_owned();
        let rsa_public_key_pem = match value.get("publicKey") {
            None => None,
            Some(pk) => {
                // Tolerant on missing owner, strict on present-but-wrong
                // (same rule as the strict decode).
                if let Some(owner) = pk.get("owner").and_then(Value::as_str) {
                    if owner != id_str {
                        return Err(ActorError::InvalidField {
                            name: "publicKey.owner".into(),
                            reason: format!("owner {owner:?} does not match Actor id {id_str:?}"),
                        });
                    }
                }
                pk.get("publicKeyPem")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            }
        };
        let attestation_v2 = match value.get(PQ_ATTESTATION_V2_PROPERTY_URI) {
            None => None,
            Some(raw) => Some(
                serde_json::from_value::<ActorAttestationV2>(raw.clone())
                    .map_err(|e| ActorError::Attestation(format!("v2: {e}")))?,
            ),
        };
        Ok(Self {
            id,
            inbox,
            preferred_username,
            rsa_public_key_pem,
            attestation_v2,
        })
    }

    /// Verify the v2 attestation, returning the derived agent id hex.
    /// Fails closed when either the attestation or the RSA key is
    /// absent; callers render the public-only card on any error.
    ///
    /// # Errors
    ///
    /// [`ActorError`] wrapping the attestation failure surface.
    pub fn verify_attestation_v2(&self) -> Result<String, ActorError> {
        let att = self
            .attestation_v2
            .as_ref()
            .ok_or_else(|| ActorError::Attestation("no v2 attestation on actor".into()))?;
        let pem = self
            .rsa_public_key_pem
            .as_deref()
            .ok_or_else(|| ActorError::MissingField {
                name: "publicKey.publicKeyPem".into(),
            })?;
        let spki_der = spki_pem_to_der(pem).map_err(|reason| ActorError::InvalidField {
            name: "publicKey.publicKeyPem".into(),
            reason,
        })?;
        Ok(crate::attestation::verify_binding_v2(
            &self.preferred_username,
            &self.id,
            &spki_der,
            att,
        )?)
    }
}

/// Fetch and tolerantly decode a remote actor. Same SSRF hardening as
/// [`crate::actor::fetch_actor`] (private-IP pre-flight, DNS pinning,
/// no redirects, body cap, timeout).
///
/// # Errors
///
/// Same [`FetchActorError`] surface as the strict fetch.
pub async fn fetch_remote_actor(actor_url: &url::Url) -> Result<RemoteActor, FetchActorError> {
    let client = pinned_no_redirect_client(actor_url, ACTOR_FETCH_TIMEOUT).await?;
    let value = fetch_json_ld_at_url(&client, actor_url, ACTOR_FETCH_TIMEOUT).await?;
    RemoteActor::from_json_ld(&value).map_err(FetchActorError::Parse)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn fixture() -> Value {
        serde_json::from_str(include_str!("../tests/fixtures/gargron_actor.json")).unwrap()
    }

    #[test]
    fn vanilla_actor_without_attestation_decodes_with_none() {
        let mut v = fixture();
        v.as_object_mut()
            .unwrap()
            .remove(crate::actor::PQ_ATTESTATION_PROPERTY_URI);
        let actor = RemoteActor::from_json_ld(&v).unwrap();
        assert!(actor.attestation_v2.is_none());
        assert!(actor.rsa_public_key_pem.is_some());
        assert_eq!(actor.preferred_username, "gargron");
    }

    // The inbox is what we POST Follow/Create/DM activities to. It must
    // decode for a plain Mastodon actor that carries no PQ attestation —
    // this is the type delivery uses so a non-fetchit target is reachable.
    #[test]
    fn remote_actor_exposes_inbox_without_attestation() {
        let mut v = fixture();
        v.as_object_mut()
            .unwrap()
            .remove(crate::actor::PQ_ATTESTATION_PROPERTY_URI);
        let actor = RemoteActor::from_json_ld(&v).unwrap();
        assert_eq!(
            actor.inbox.as_str(),
            "https://mastodon.example/users/gargron/inbox"
        );
    }

    // An actor doc missing the mandatory `inbox` is malformed and useless
    // for delivery — decode must fail rather than yield an unreachable actor.
    #[test]
    fn remote_actor_missing_inbox_is_rejected() {
        let mut v = fixture();
        v.as_object_mut().unwrap().remove("inbox");
        assert!(RemoteActor::from_json_ld(&v).is_err());
    }

    #[test]
    fn actor_without_public_key_decodes_with_none_pem() {
        let mut v = fixture();
        let obj = v.as_object_mut().unwrap();
        obj.remove(crate::actor::PQ_ATTESTATION_PROPERTY_URI);
        obj.remove("publicKey");
        let actor = RemoteActor::from_json_ld(&v).unwrap();
        assert!(actor.rsa_public_key_pem.is_none());
    }

    #[test]
    fn non_actor_class_is_rejected() {
        let mut v = fixture();
        v.as_object_mut()
            .unwrap()
            .insert("type".into(), serde_json::json!("Note"));
        assert!(RemoteActor::from_json_ld(&v).is_err());
    }

    #[test]
    fn forged_public_key_owner_is_rejected() {
        let mut v = fixture();
        v.as_object_mut()
            .unwrap()
            .remove(crate::actor::PQ_ATTESTATION_PROPERTY_URI);
        v["publicKey"]["owner"] = serde_json::json!("https://evil.example/actors/mallory");
        assert!(RemoteActor::from_json_ld(&v).is_err());
    }

    #[test]
    fn malformed_v2_attestation_is_a_hard_error() {
        let mut v = fixture();
        v.as_object_mut().unwrap().insert(
            PQ_ATTESTATION_V2_PROPERTY_URI.into(),
            serde_json::json!("garbage"),
        );
        assert!(RemoteActor::from_json_ld(&v).is_err());
    }

    #[test]
    fn v2_attestation_is_decoded_and_verifies() {
        let actor_url: url::Url = "https://etchit.io/actors/josh".parse().unwrap();
        let spki_der = vec![7u8; 16];
        let pem = crate::actor::spki_der_to_pem(&spki_der);
        let (att2, derived) = crate::attestation::test_attested_v2(
            "josh",
            &actor_url,
            &spki_der,
            &"a".repeat(64),
            "https://relay.example/",
            3,
        );
        let v = serde_json::json!({
            "id": actor_url.as_str(),
            "type": "Person",
            "preferredUsername": "josh",
            "inbox": format!("{}/inbox", actor_url.as_str()),
            "publicKey": { "owner": actor_url.as_str(), "publicKeyPem": pem },
            PQ_ATTESTATION_V2_PROPERTY_URI: serde_json::to_value(&att2).unwrap(),
        });
        let actor = RemoteActor::from_json_ld(&v).unwrap();
        assert_eq!(actor.attestation_v2, Some(att2));
        assert_eq!(actor.verify_attestation_v2().unwrap(), derived);
    }

    #[test]
    fn verify_without_attestation_or_pem_fails_closed() {
        let v = serde_json::json!({
            "id": "https://x.example/a",
            "type": "Person",
            "preferredUsername": "a",
            "inbox": "https://x.example/a/inbox",
        });
        let actor = RemoteActor::from_json_ld(&v).unwrap();
        assert!(actor.verify_attestation_v2().is_err());

        // Attestation present but no RSA key: still fails closed.
        let actor_url: url::Url = "https://etchit.io/actors/a".parse().unwrap();
        let (att2, _) = crate::attestation::test_attested_v2(
            "a",
            &actor_url,
            &[1],
            &"a".repeat(64),
            "https://relay.example/",
            1,
        );
        let v2 = serde_json::json!({
            "id": actor_url.as_str(),
            "type": "Person",
            "preferredUsername": "a",
            "inbox": format!("{}/inbox", actor_url.as_str()),
            PQ_ATTESTATION_V2_PROPERTY_URI: serde_json::to_value(&att2).unwrap(),
        });
        let actor2 = RemoteActor::from_json_ld(&v2).unwrap();
        assert!(actor2.verify_attestation_v2().is_err());
    }

    #[test]
    fn tampered_v2_attestation_fails_verification() {
        let actor_url: url::Url = "https://etchit.io/actors/josh".parse().unwrap();
        let spki_der = vec![7u8; 16];
        let pem = crate::actor::spki_der_to_pem(&spki_der);
        let (mut att2, _) = crate::attestation::test_attested_v2(
            "josh",
            &actor_url,
            &spki_der,
            &"a".repeat(64),
            "https://relay.example/",
            3,
        );
        att2.relay_hint = "https://evil.example/".into();
        let v = serde_json::json!({
            "id": actor_url.as_str(),
            "type": "Person",
            "preferredUsername": "josh",
            "inbox": format!("{}/inbox", actor_url.as_str()),
            "publicKey": { "owner": actor_url.as_str(), "publicKeyPem": pem },
            PQ_ATTESTATION_V2_PROPERTY_URI: serde_json::to_value(&att2).unwrap(),
        });
        let actor = RemoteActor::from_json_ld(&v).unwrap();
        assert!(actor.verify_attestation_v2().is_err());
    }
}
