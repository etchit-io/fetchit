//! Capability-token verification + resolution.

use crate::error::ServerError;
use crate::signature::SignatureVerifier;
use fetchit_relay_proto::{to_bytes, AgentId, CapabilityToken, EffectiveCapabilities, Region};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Resolves a (possibly absent) capability token into a session
/// limit snapshot, after verifying the issuer's signature.
pub struct CapabilityResolver {
    issuer_keys: HashMap<String, Vec<u8>>,
}

impl CapabilityResolver {
    /// Build a resolver with the supplied trust anchors.
    #[must_use]
    pub fn new(issuer_keys: HashMap<String, Vec<u8>>) -> Self {
        Self { issuer_keys }
    }

    /// Validate `token` and return the effective per-session limits.
    ///
    /// Returns the default profile when `token` is `None`.
    ///
    /// # Errors
    /// Returns a [`ServerError`] variant when the token is signed by
    /// an unknown issuer, doesn't match the bound agent, is expired,
    /// has an invalid signature, or restricts to a different region.
    pub fn resolve(
        &self,
        token: Option<&CapabilityToken>,
        verifier: &dyn SignatureVerifier,
        bound_agent: &AgentId,
        region: &Region,
    ) -> Result<EffectiveCapabilities, ServerError> {
        let Some(token) = token else {
            return Ok(EffectiveCapabilities::default_profile());
        };

        let Some(issuer_pk) = self.issuer_keys.get(&token.claims.issuer_key_id) else {
            return Err(ServerError::CapabilityInvalid(
                "unknown issuer key id".into(),
            ));
        };
        if &token.claims.agent_id != bound_agent {
            return Err(ServerError::CapabilityInvalid(
                "agent_id does not match session".into(),
            ));
        }
        if token.claims.expires_at_ms <= now_ms() {
            return Err(ServerError::CapabilityInvalid("token expired".into()));
        }
        let claim_bytes = to_bytes(&token.claims).map_err(ServerError::Proto)?;
        if !verifier.verify_ml_dsa_65(issuer_pk, &claim_bytes, &token.signature) {
            return Err(ServerError::CapabilityInvalid(
                "issuer signature invalid".into(),
            ));
        }

        let eff = EffectiveCapabilities::from_claims(&token.claims.capabilities);
        if !eff.permits_region(region) {
            return Err(ServerError::RegionDenied {
                region: region.to_string(),
            });
        }
        Ok(eff)
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::signature::AcceptAllVerifier;
    use fetchit_relay_proto::{
        Capability, CapabilityClaims, CapabilityToken, FeatureFlag, TenantId,
    };
    use std::collections::BTreeSet;

    fn bound() -> AgentId {
        AgentId::from_bytes([0x11; 32])
    }

    fn claims(agent: AgentId, caps: Vec<Capability>) -> CapabilityClaims {
        CapabilityClaims {
            agent_id: agent,
            tenant_id: None,
            issued_at_ms: 1,
            expires_at_ms: u64::MAX,
            capabilities: caps,
            issuer_key_id: "issuer-v1".to_owned(),
        }
    }

    fn token(claims: CapabilityClaims) -> CapabilityToken {
        CapabilityToken {
            claims,
            signature: vec![0u8; 16],
        }
    }

    fn resolver_with_issuer() -> CapabilityResolver {
        let mut m = HashMap::new();
        m.insert("issuer-v1".to_owned(), b"issuer-pub-key".to_vec());
        CapabilityResolver::new(m)
    }

    #[test]
    fn absent_token_yields_default_profile() {
        let r = resolver_with_issuer();
        let eff = r
            .resolve(None, &AcceptAllVerifier, &bound(), &Region::Nyc)
            .unwrap();
        assert_eq!(eff, EffectiveCapabilities::default_profile());
    }

    #[test]
    fn unknown_issuer_is_rejected() {
        let r = resolver_with_issuer();
        let mut c = claims(bound(), vec![]);
        c.issuer_key_id = "nope".into();
        let err = r
            .resolve(Some(&token(c)), &AcceptAllVerifier, &bound(), &Region::Nyc)
            .unwrap_err();
        assert!(matches!(err, ServerError::CapabilityInvalid(_)));
    }

    #[test]
    fn agent_mismatch_is_rejected() {
        let r = resolver_with_issuer();
        let c = claims(AgentId::from_bytes([0x22; 32]), vec![]);
        let err = r
            .resolve(Some(&token(c)), &AcceptAllVerifier, &bound(), &Region::Nyc)
            .unwrap_err();
        assert!(matches!(err, ServerError::CapabilityInvalid(_)));
    }

    #[test]
    fn expired_token_is_rejected() {
        let r = resolver_with_issuer();
        let mut c = claims(bound(), vec![]);
        c.expires_at_ms = 1;
        let err = r
            .resolve(Some(&token(c)), &AcceptAllVerifier, &bound(), &Region::Nyc)
            .unwrap_err();
        assert!(matches!(err, ServerError::CapabilityInvalid(_)));
    }

    #[test]
    fn region_outside_allowlist_is_rejected() {
        let r = resolver_with_issuer();
        let regions: BTreeSet<Region> = [Region::Fra].into_iter().collect();
        let c = claims(bound(), vec![Capability::AllowedRegions(regions)]);
        let err = r
            .resolve(Some(&token(c)), &AcceptAllVerifier, &bound(), &Region::Nyc)
            .unwrap_err();
        assert!(matches!(err, ServerError::RegionDenied { .. }));
    }

    #[test]
    fn features_and_admin_flow_through() {
        let r = resolver_with_issuer();
        let c = claims(
            bound(),
            vec![
                Capability::AdminFor(TenantId::new("acme")),
                Capability::Feature(FeatureFlag::Voice),
            ],
        );
        let eff = r
            .resolve(Some(&token(c)), &AcceptAllVerifier, &bound(), &Region::Nyc)
            .unwrap();
        assert!(eff.admin_for.contains(&TenantId::new("acme")));
        assert!(eff.features.contains(&FeatureFlag::Voice));
    }
}
