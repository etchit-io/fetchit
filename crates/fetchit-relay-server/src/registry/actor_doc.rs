//! Build the `ActivityPub` actor document. The document carries the
//! `publicKeyPem` and the v2 attestation under
//! `PQ_ATTESTATION_V2_PROPERTY_URI` so any client verifies the full
//! chain offline.

use crate::registry::ActorRecord;
use fetchit_fedi::actor::{spki_der_to_pem, PQ_ATTESTATION_V2_PROPERTY_URI};
use serde_json::{json, Map, Value};

/// Build the actor JSON-LD document for a stored record. Built via an
/// explicit [`Map`] so the dynamic attestation property URI can be a
/// runtime key (the `json!` macro only takes literal keys) and so no
/// `.unwrap()` is needed in this non-test code.
#[must_use]
pub fn actor_document(record: &ActorRecord) -> Value {
    let pem = spki_der_to_pem(&record.rsa_spki_der);
    // ActorAttestationV2 is plain data (strings + u64 + base64 bytes);
    // serialization is infallible, so `Null` here is an unreachable
    // defensive default that keeps this function panic-free.
    let attestation_value = serde_json::to_value(&record.attestation).unwrap_or(Value::Null);

    let mut map = Map::new();
    map.insert(
        "@context".to_string(),
        json!([
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/v1"
        ]),
    );
    map.insert("id".to_string(), json!(record.actor_url));
    map.insert("type".to_string(), json!("Person"));
    map.insert("preferredUsername".to_string(), json!(record.handle));
    // Point `inbox` at the bridge's shared inbox (a real served route),
    // NOT `<actor_url>/inbox` which 404s (Alice F3). Discovery (M5.1)
    // never dereferences this; remote Follow delivery (M5.2) will. The
    // origin is derived from the actor_url, so no domain threading is
    // needed. M5.2 finalizes the full federation inbox semantics.
    let shared_inbox = record.actor_url.split("/actors/").next().map_or_else(
        || format!("{}/inbox", record.actor_url),
        |origin| format!("{origin}/inbox"),
    );
    map.insert("inbox".to_string(), json!(shared_inbox.clone()));
    map.insert(
        "endpoints".to_string(),
        json!({ "sharedInbox": shared_inbox }),
    );
    map.insert(
        "publicKey".to_string(),
        json!({
            "id": format!("{}#main-key", record.actor_url),
            "owner": record.actor_url,
            "publicKeyPem": pem,
        }),
    );
    map.insert(
        PQ_ATTESTATION_V2_PROPERTY_URI.to_string(),
        attestation_value,
    );
    Value::Object(map)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::registry::{verify_registration, RegistryConfig};
    use fetchit_fedi::lookup::RemoteActor;
    use fetchit_fedi::registry::RegisterActorRequest;

    fn valid_record() -> ActorRecord {
        let cfg = RegistryConfig::new("etchit.io");
        let req: RegisterActorRequest = serde_json::from_str(include_str!(
            "../../../fetchit-fedi/tests/fixtures/registry-v1/register-request-valid.json"
        ))
        .unwrap();
        verify_registration(&cfg, &req, 1).unwrap()
    }

    #[test]
    fn served_doc_round_trips_through_client_decoder_and_verifies() {
        let record = valid_record();
        let doc = actor_document(&record);
        // Feed the SERVED doc back through fetchit-fedi's own tolerant
        // client decoder + attestation verify: the chain must close, and
        // the derived agent id must equal what we stored.
        let remote = RemoteActor::from_json_ld(&doc).expect("client decodes served doc");
        let derived = remote
            .verify_attestation_v2()
            .expect("attestation verifies offline");
        assert_eq!(derived, record.agent_id_hex);
        assert_eq!(remote.preferred_username, "josh");
        assert_eq!(remote.id.as_str(), "https://etchit.io/actors/josh");
    }

    #[test]
    fn doc_has_pem_and_attestation_slots() {
        let record = valid_record();
        let doc = actor_document(&record);
        assert_eq!(doc["type"], "Person");
        assert!(doc["publicKey"]["publicKeyPem"]
            .as_str()
            .unwrap()
            .contains("BEGIN PUBLIC KEY"));
        assert!(doc.get(PQ_ATTESTATION_V2_PROPERTY_URI).is_some());
    }
}
