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
    /// `outbox` collection URL when served (every Mastodon-family actor
    /// has one; optional here so exotic actors still decode).
    pub outbox: Option<url::Url>,
    /// `publicKey.publicKeyPem` when served.
    pub rsa_public_key_pem: Option<String>,
    /// v2 attestation when served. Present-but-malformed is a decode
    /// error, never silently `None`.
    pub attestation_v2: Option<ActorAttestationV2>,
    /// The actor's avatar URL as served in `icon`, when present. Pure
    /// remote input: nothing here is validated at decode time —
    /// [`crate::avatar::fetch_avatar`] owns the https + SSRF + size +
    /// content-type gates. `None` for an actor with no usable icon.
    pub icon_url: Option<String>,
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
        let outbox = value
            .get("outbox")
            .and_then(Value::as_str)
            .and_then(|s| s.parse().ok());
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
        let icon_url = crate::avatar::icon_url_from_actor_doc(value);
        Ok(Self {
            id,
            inbox,
            preferred_username,
            outbox,
            rsa_public_key_pem,
            attestation_v2,
            icon_url,
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
/// The returned document's `id` is BOUND to the URL it was fetched
/// from: an `id` differing from the fetch URL is trusted only after one
/// re-fetch AT the claimed id confirms the same claim (the Mastodon
/// rule). Without this, any host could serve a document impersonating
/// an actor it does not control, and every downstream sender binding —
/// inbox dispatch, the follow-request queue, follower fan-out records —
/// would be forgeable by a hostile instance.
///
/// # Errors
///
/// Same [`FetchActorError`] surface as the strict fetch, plus
/// [`FetchActorError::IdMismatch`] when the claimed id fails to
/// self-confirm.
pub async fn fetch_remote_actor(actor_url: &url::Url) -> Result<RemoteActor, FetchActorError> {
    let actor = fetch_remote_actor_once(actor_url).await?;
    if actor.id == *actor_url {
        return Ok(actor);
    }
    // Exactly one hop: the claimed id must serve a document naming
    // itself. The re-fetch rides the same SSRF-guarded client path.
    let claimed = actor.id.clone();
    let refetched = fetch_remote_actor_once(&claimed).await?;
    if refetched.id == claimed {
        Ok(refetched)
    } else {
        Err(FetchActorError::IdMismatch {
            fetched_from: actor_url.to_string(),
            claimed: refetched.id.to_string(),
        })
    }
}

async fn fetch_remote_actor_once(actor_url: &url::Url) -> Result<RemoteActor, FetchActorError> {
    let client = pinned_no_redirect_client(actor_url, ACTOR_FETCH_TIMEOUT).await?;
    let value = fetch_json_ld_at_url(&client, actor_url, ACTOR_FETCH_TIMEOUT).await?;
    RemoteActor::from_json_ld(&value).map_err(FetchActorError::Parse)
}

/// One post from a remote actor's outbox, reduced to what a feed
/// renders. `content_html` is the wire HTML as served — callers strip
/// it with [`crate::text::html_to_text`] before display; it must never
/// reach a renderer raw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemotePost {
    /// Author actor URL (`attributedTo`, falling back to the wrapping
    /// activity's `actor`).
    pub author_url: String,
    /// The Note's `content` — raw HTML off the wire.
    pub content_html: String,
    /// ISO-8601 `published` stamp as served (empty when absent). UTC
    /// ISO-8601 sorts lexicographically, so feeds can order on the
    /// string without a datetime parse.
    pub published: String,
    /// Human-facing URL of the post (`url`, falling back to `id`).
    pub object_url: String,
}

fn post_from_note(note: &Value, fallback_author: Option<&str>) -> Option<RemotePost> {
    let author_url = note
        .get("attributedTo")
        .and_then(Value::as_str)
        .or(fallback_author)?
        .to_owned();
    let content_html = note
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if content_html.is_empty() {
        return None;
    }
    let published = note
        .get("published")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let object_url = note
        .get("url")
        .and_then(Value::as_str)
        .or_else(|| note.get("id").and_then(Value::as_str))
        .unwrap_or_default()
        .to_owned();
    Some(RemotePost {
        author_url,
        content_html,
        published,
        object_url,
    })
}

/// Pure parse: collect the `Create(Note)` items (and tolerated bare
/// `Note` items) from an outbox page's `orderedItems`, newest-first as
/// served, capped at `cap`. Boosts (`Announce`) and non-Note objects
/// are skipped — the v1 feed renders authored text posts only.
#[must_use]
pub fn posts_from_outbox_page(page: &Value, cap: usize) -> Vec<RemotePost> {
    let Some(items) = page.get("orderedItems").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in items {
        if out.len() >= cap {
            break;
        }
        let kind = item.get("type").and_then(Value::as_str).unwrap_or("");
        let post = match kind {
            "Create" => {
                let activity_actor = item.get("actor").and_then(Value::as_str);
                match item.get("object") {
                    Some(obj) if obj.get("type").and_then(Value::as_str) == Some("Note") => {
                        post_from_note(obj, activity_actor)
                    }
                    _ => None,
                }
            }
            "Note" => post_from_note(item, None),
            _ => None,
        };
        if let Some(p) = post {
            out.push(p);
        }
    }
    out
}

/// Fetch the newest posts from an actor's outbox: GET the collection,
/// follow its `first` page when the items aren't inline (the
/// Mastodon-family shape), and reduce to at most `cap` [`RemotePost`]s.
/// Same SSRF hardening as [`fetch_remote_actor`] on both requests.
///
/// # Errors
///
/// Same [`FetchActorError`] surface as the actor fetch; a page with no
/// parsable items is `Ok(vec![])`, not an error (fail-open to an empty
/// feed entry, never a broken feed).
pub async fn fetch_outbox_posts(
    outbox: &url::Url,
    cap: usize,
) -> Result<Vec<RemotePost>, FetchActorError> {
    let client = pinned_no_redirect_client(outbox, ACTOR_FETCH_TIMEOUT).await?;
    let collection = fetch_json_ld_at_url(&client, outbox, ACTOR_FETCH_TIMEOUT).await?;
    if collection.get("orderedItems").is_some() {
        return Ok(posts_from_outbox_page(&collection, cap));
    }
    match collection.get("first") {
        Some(Value::String(first_url)) => {
            let Ok(first) = first_url.parse::<url::Url>() else {
                return Ok(Vec::new());
            };
            let client = pinned_no_redirect_client(&first, ACTOR_FETCH_TIMEOUT).await?;
            let page = fetch_json_ld_at_url(&client, &first, ACTOR_FETCH_TIMEOUT).await?;
            Ok(posts_from_outbox_page(&page, cap))
        }
        Some(embedded @ Value::Object(_)) => Ok(posts_from_outbox_page(embedded, cap)),
        _ => Ok(Vec::new()),
    }
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

    #[test]
    fn remote_actor_exposes_outbox_when_served() {
        let mut v = fixture();
        v["outbox"] = serde_json::json!("https://mastodon.example/users/g/outbox");
        let actor = RemoteActor::from_json_ld(&v).unwrap();
        assert_eq!(
            actor.outbox.unwrap().as_str(),
            "https://mastodon.example/users/g/outbox"
        );
        // Absent outbox stays None — exotic actors still decode.
        let mut bare = fixture();
        bare.as_object_mut().unwrap().remove("outbox");
        assert!(RemoteActor::from_json_ld(&bare).unwrap().outbox.is_none());
    }

    #[test]
    fn remote_actor_carries_the_icon_url_when_served() {
        let mut v = fixture();
        v.as_object_mut()
            .unwrap()
            .remove(crate::actor::PQ_ATTESTATION_PROPERTY_URI);
        v["icon"] = serde_json::json!({
            "type": "Image", "mediaType": "image/png",
            "url": "https://files.mastodon.example/avatars/1.png"
        });
        let actor = RemoteActor::from_json_ld(&v).unwrap();
        assert_eq!(
            actor.icon_url.as_deref(),
            Some("https://files.mastodon.example/avatars/1.png")
        );

        // An actor with no icon decodes exactly as before — the avatar
        // is additive, never a decode requirement.
        let mut bare = fixture();
        bare.as_object_mut().unwrap().remove("icon");
        assert!(RemoteActor::from_json_ld(&bare).unwrap().icon_url.is_none());
    }

    fn outbox_page() -> Value {
        serde_json::json!({
            "type": "OrderedCollectionPage",
            "orderedItems": [
                {
                    "type": "Create",
                    "actor": "https://m.example/users/g",
                    "object": {
                        "type": "Note",
                        "attributedTo": "https://m.example/users/g",
                        "content": "<p>hello <b>world</b></p>",
                        "published": "2026-07-13T06:00:00Z",
                        "url": "https://m.example/@g/1"
                    }
                },
                { "type": "Announce", "object": "https://elsewhere.example/x" },
                {
                    "type": "Create",
                    "actor": "https://m.example/users/g",
                    "object": { "type": "Image", "url": "https://m.example/i/2" }
                },
                {
                    "type": "Note",
                    "attributedTo": "https://m.example/users/g",
                    "content": "bare note",
                    "id": "https://m.example/notes/3"
                }
            ]
        })
    }

    #[test]
    fn outbox_page_reduces_to_authored_notes_only() {
        let posts = posts_from_outbox_page(&outbox_page(), 10);
        assert_eq!(posts.len(), 2, "boosts + non-Note objects skipped");
        assert_eq!(posts[0].author_url, "https://m.example/users/g");
        assert_eq!(posts[0].content_html, "<p>hello <b>world</b></p>");
        assert_eq!(posts[0].published, "2026-07-13T06:00:00Z");
        assert_eq!(posts[0].object_url, "https://m.example/@g/1");
        // Bare Note falls back to its id for the object url.
        assert_eq!(posts[1].object_url, "https://m.example/notes/3");
    }

    #[test]
    fn outbox_page_honors_cap_and_tolerates_junk() {
        assert_eq!(posts_from_outbox_page(&outbox_page(), 1).len(), 1);
        assert!(posts_from_outbox_page(&serde_json::json!({}), 10).is_empty());
        assert!(
            posts_from_outbox_page(&serde_json::json!({"orderedItems": "nope"}), 10).is_empty()
        );
        // A Note with no content renders nothing worth feeding.
        let empty = serde_json::json!({"orderedItems":[
            {"type":"Note","attributedTo":"https://m.example/u/g","content":""}
        ]});
        assert!(posts_from_outbox_page(&empty, 10).is_empty());
    }
}
