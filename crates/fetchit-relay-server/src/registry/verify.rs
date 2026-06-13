//! Pure registry verification: handle policy, canonical actor URL,
//! SO-4 SPKI parse, and the `verify_binding_v2` call. No axum, no IO.

use crate::registry::{ActorRecord, RegistryRejection};
use fetchit_fedi::registry::RegisterActorRequest;

/// Server config for the bridge role.
#[derive(Clone, Debug)]
pub struct RegistryConfig {
    /// The domain this bridge is authoritative for, e.g. `etchit.io`.
    pub domain: String,
    /// Header carrying the authoritative client IP for rate limiting.
    /// The CF Worker forwards `CF-Connecting-IP` (Cloudflare-set,
    /// not client-forgeable) into this header; the rate limiter keys on
    /// it, never on leftmost `X-Forwarded-For`. See [`crate::registry`]
    /// router source-key extraction.
    pub trusted_client_ip_header: String,
}

impl RegistryConfig {
    /// Config for `domain` with the default trusted client-IP header
    /// (`x-real-ip`).
    #[must_use]
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            trusted_client_ip_header: "x-real-ip".to_string(),
        }
    }
}

/// Validate a handle against the SO-3 policy: `[a-z0-9_-]`, 1..=64,
/// lowercase-only. Mirrors `fetchit-chat`'s private `validate_actor_handle`
/// (restated here so the relay-server does not depend on fetchit-chat).
/// Uppercase is rejected, never silently lowercased — the signature was
/// over the exact handle bytes.
///
/// # Errors
/// [`RegistryRejection::Handle`] on any violation (maps to HTTP 422).
pub fn validate_registry_handle(handle: &str) -> Result<(), RegistryRejection> {
    if handle.is_empty() {
        return Err(RegistryRejection::Handle("handle must be non-empty".into()));
    }
    if handle.len() > 64 {
        return Err(RegistryRejection::Handle("handle exceeds 64 chars".into()));
    }
    for b in handle.bytes() {
        if !matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-') {
            return Err(RegistryRejection::Handle(format!(
                "char {:?} not allowed; handles are lowercase [a-z0-9_-]",
                b as char
            )));
        }
    }
    Ok(())
}

/// Build the canonical `https://<domain>/actors/<handle>` URL (SO-1).
/// Validates the handle first so the path is always well-formed and the
/// `as_str()` form byte-matches the string the client signed over.
///
/// # Errors
/// [`RegistryRejection::Handle`] for a bad handle; [`RegistryRejection::Body`]
/// if URL assembly fails (domain misconfig).
pub fn canonical_actor_url(
    cfg: &RegistryConfig,
    handle: &str,
) -> Result<url::Url, RegistryRejection> {
    validate_registry_handle(handle)?;
    url::Url::parse(&format!("https://{}/actors/{}", cfg.domain, handle))
        .map_err(|e| RegistryRejection::Body(format!("actor url assembly: {e}")))
}

/// Verify a registration/update request against the bridge's domain.
/// Order: validate handle (422) -> build canonical URL -> SO-4 SPKI
/// parse (422) -> `verify_binding_v2` (422) -> assemble [`ActorRecord`]
/// with the DERIVED agent id. `now_ms` stamps `registered_at_ms`.
///
/// # Errors
/// [`RegistryRejection`] (every variant maps to HTTP 422).
pub fn verify_registration(
    cfg: &RegistryConfig,
    req: &RegisterActorRequest,
    now_ms: u64,
) -> Result<ActorRecord, RegistryRejection> {
    let actor_url = canonical_actor_url(cfg, &req.handle)?;

    // SO-4: parse-validate the SPKI so the served publicKeyPem is a real
    // RSA key. verify_binding_v2 covers the SPKI bytes in the signed
    // input but does not parse them as a key.
    use rsa::pkcs8::DecodePublicKey;
    rsa::RsaPublicKey::from_public_key_der(&req.rsa_spki_der)
        .map_err(|e| RegistryRejection::Spki(e.to_string()))?;

    let agent_id_hex = fetchit_fedi::attestation::verify_binding_v2(
        &req.handle,
        &actor_url,
        &req.rsa_spki_der,
        &req.attestation_v2,
    )
    .map_err(|e| RegistryRejection::Attestation(e.to_string()))?;

    Ok(ActorRecord {
        handle: req.handle.clone(),
        actor_url: actor_url.as_str().to_string(),
        agent_id_hex,
        rsa_spki_der: req.rsa_spki_der.clone(),
        attestation: req.attestation_v2.clone(),
        registered_at_ms: now_ms,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn valid_request() -> RegisterActorRequest {
        serde_json::from_str(include_str!(
            "../../../fetchit-fedi/tests/fixtures/registry-v1/register-request-valid.json"
        ))
        .expect("valid fixture parses")
    }

    // ---- Task 4: handle policy (SO-3) ----

    #[test]
    fn accepts_lowercase_digits_underscore_dash() {
        for h in ["josh", "alice_42", "ab-c-d", "x", &"a".repeat(64)] {
            assert!(validate_registry_handle(h).is_ok(), "{h}");
        }
    }

    #[test]
    fn rejects_uppercase_empty_long_and_path_chars() {
        for bad in [
            "JOSH", "Josh", "alice_42_U", "", &"a".repeat(65), "a.b", "a/b", "a b", "a@b",
        ] {
            assert!(validate_registry_handle(bad).is_err(), "{bad}");
        }
    }

    // ---- Task 5: canonical actor_url (SO-1) ----

    #[test]
    fn canonical_url_is_byte_exact_no_trailing_slash() {
        let cfg = RegistryConfig::new("etchit.io");
        let url = canonical_actor_url(&cfg, "josh").unwrap();
        assert_eq!(url.as_str(), "https://etchit.io/actors/josh");
    }

    #[test]
    fn canonical_url_rejects_invalid_handle() {
        let cfg = RegistryConfig::new("etchit.io");
        assert!(canonical_actor_url(&cfg, "Josh").is_err());
        assert!(canonical_actor_url(&cfg, "a/b").is_err());
    }

    // ---- Task 6: verification core (SO-4 + verify_binding_v2) ----

    #[test]
    fn committed_valid_fixture_registers_and_derives_agent_id() {
        let cfg = RegistryConfig::new("etchit.io");
        let record = verify_registration(&cfg, &valid_request(), 1234).expect("must verify");
        assert_eq!(record.handle, "josh");
        assert_eq!(record.actor_url, "https://etchit.io/actors/josh");
        assert_eq!(record.agent_id_hex.len(), 64);
        assert!(record
            .agent_id_hex
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        assert_eq!(record.registered_at_ms, 1234);
    }

    #[test]
    fn uppercase_handle_is_rejected() {
        let cfg = RegistryConfig::new("etchit.io");
        let mut req = valid_request();
        req.handle = "Josh".into();
        assert!(matches!(
            verify_registration(&cfg, &req, 1).unwrap_err(),
            RegistryRejection::Handle(_)
        ));
    }

    #[test]
    fn tampered_attestation_is_rejected() {
        let cfg = RegistryConfig::new("etchit.io");
        let mut req = valid_request();
        req.attestation_v2.relay_hint = "https://evil.example/".into();
        assert!(matches!(
            verify_registration(&cfg, &req, 1).unwrap_err(),
            RegistryRejection::Attestation(_)
        ));
    }

    #[test]
    fn wrong_version_is_rejected() {
        let cfg = RegistryConfig::new("etchit.io");
        let mut req = valid_request();
        req.attestation_v2.version = 1;
        assert!(matches!(
            verify_registration(&cfg, &req, 1).unwrap_err(),
            RegistryRejection::Attestation(_)
        ));
    }

    #[test]
    fn garbage_spki_is_rejected() {
        let cfg = RegistryConfig::new("etchit.io");
        let mut req = valid_request();
        req.rsa_spki_der = vec![0xDE, 0xAD, 0xBE, 0xEF];
        // Garbage SPKI also breaks the signature (the SPKI is in the
        // signed input), so either Spki or Attestation is correct; both
        // are 422. SPKI parse runs first, so expect Spki here.
        assert!(matches!(
            verify_registration(&cfg, &req, 1).unwrap_err(),
            RegistryRejection::Spki(_) | RegistryRejection::Attestation(_)
        ));
    }
}
