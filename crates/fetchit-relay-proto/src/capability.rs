//! Capability claims carried in the auth handshake.
//!
//! A [`CapabilityToken`] is a signed bundle of [`Capability`] claims
//! that an issuer (the relay control plane) hands to a client. The
//! relay verifies the issuer signature, then applies each claim to
//! the session via [`EffectiveCapabilities`]. Absent token = the
//! default profile, which serves the public pool.

use crate::identity::{AgentId, TenantId};
use crate::region::Region;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Default per-agent send rate when no token is presented.
pub const DEFAULT_MAX_ENVELOPES_PER_MIN: u32 = 60;

/// Default per-envelope wire size cap when no token is presented.
pub const DEFAULT_MAX_ENVELOPE_BYTES: u32 = 1_572_864;

/// Default upper bound on group membership when no token is presented.
pub const DEFAULT_MAX_GROUP_SIZE: u32 = 10;

/// Extensible feature flags a token can light up for a session.
///
/// Added as the relay learns new capabilities; old binaries reject
/// unknown flags safely because the relay applies only the flags it
/// recognises.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FeatureFlag {
    /// Connection may upload sealed-to-user-key backups to the
    /// backup service (handled out of band; relay just lights up
    /// the routing).
    EncryptedBackup,
    /// Connection may negotiate voice call setup envelopes.
    Voice,
    /// Connection may negotiate video call setup envelopes.
    Video,
    /// Connection may route large file-transfer envelopes.
    FileTransfer,
    /// Connection may publish to a tenant's audit-event topic.
    AuditPublish,
    /// Connection may consume a tenant's audit-event topic.
    AuditConsume,
}

/// One concrete capability claim.
///
/// Each claim widens what the relay will accept on the session
/// beyond the default profile. Servers ignore claims they don't
/// recognise so newer issuers stay forward-compatible.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Capability {
    /// Override per-minute send rate cap.
    MaxEnvelopesPerMin(u32),
    /// Override per-envelope byte cap.
    MaxEnvelopeBytes(u32),
    /// Override maximum group size the client may operate in.
    MaxGroupSize(u32),
    /// Restrict which regions this token is valid in.
    AllowedRegions(BTreeSet<Region>),
    /// Connection acts as admin for a tenant.
    AdminFor(TenantId),
    /// Enable a feature flag.
    Feature(FeatureFlag),
}

/// Issuer-signed claims envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityClaims {
    /// Agent the token is bound to.
    pub agent_id: AgentId,
    /// Tenant binding, if any.
    pub tenant_id: Option<TenantId>,
    /// Issuance time, milliseconds since the Unix epoch.
    pub issued_at_ms: u64,
    /// Expiry time, milliseconds since the Unix epoch.
    pub expires_at_ms: u64,
    /// Claims widening the default profile.
    pub capabilities: Vec<Capability>,
    /// Opaque tag identifying which issuer key signed this token.
    pub issuer_key_id: String,
}

/// Signed capability bundle.
///
/// The signature covers the postcard encoding of [`CapabilityClaims`].
/// Verification: re-encode the claims, then verify with the issuer's
/// public key looked up by [`CapabilityClaims::issuer_key_id`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityToken {
    /// The claims envelope being signed.
    pub claims: CapabilityClaims,
    /// Issuer signature over postcard-encoded `claims`.
    pub signature: Vec<u8>,
}

/// Snapshot of the resolved session limits, returned in `Ready`.
///
/// Lets clients render correct UI affordances (group-size pickers,
/// upload limits) without re-parsing the token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveCapabilities {
    /// Send rate cap, envelopes per minute.
    pub max_envelopes_per_min: u32,
    /// Per-envelope wire-size cap.
    pub max_envelope_bytes: u32,
    /// Maximum group membership.
    pub max_group_size: u32,
    /// Region restriction, if narrower than "any region".
    pub allowed_regions: Option<BTreeSet<Region>>,
    /// Tenants this session acts as admin for.
    pub admin_for: BTreeSet<TenantId>,
    /// Feature flags lit up for this session.
    pub features: BTreeSet<FeatureFlag>,
}

impl EffectiveCapabilities {
    /// Default profile applied to anonymous / no-token sessions.
    #[must_use]
    pub fn default_profile() -> Self {
        Self {
            max_envelopes_per_min: DEFAULT_MAX_ENVELOPES_PER_MIN,
            max_envelope_bytes: DEFAULT_MAX_ENVELOPE_BYTES,
            max_group_size: DEFAULT_MAX_GROUP_SIZE,
            allowed_regions: None,
            admin_for: BTreeSet::new(),
            features: BTreeSet::new(),
        }
    }

    /// Resolve claims into an effective snapshot, starting from the default.
    ///
    /// Numeric caps take the *larger* of default vs claim (claims widen,
    /// they don't tighten — a stricter default beats a permissive token).
    /// Region claim narrows from "any region". Admin and feature claims
    /// accumulate.
    #[must_use]
    pub fn from_claims(claims: &[Capability]) -> Self {
        let mut eff = Self::default_profile();
        for c in claims {
            match c {
                Capability::MaxEnvelopesPerMin(n) => {
                    eff.max_envelopes_per_min = eff.max_envelopes_per_min.max(*n);
                }
                Capability::MaxEnvelopeBytes(n) => {
                    eff.max_envelope_bytes = eff.max_envelope_bytes.max(*n);
                }
                Capability::MaxGroupSize(n) => {
                    eff.max_group_size = eff.max_group_size.max(*n);
                }
                Capability::AllowedRegions(set) => {
                    eff.allowed_regions = Some(set.clone());
                }
                Capability::AdminFor(t) => {
                    eff.admin_for.insert(t.clone());
                }
                Capability::Feature(f) => {
                    eff.features.insert(*f);
                }
            }
        }
        eff
    }

    /// True if `region` is permitted under any `AllowedRegions` claim.
    #[must_use]
    pub fn permits_region(&self, region: &Region) -> bool {
        self.allowed_regions
            .as_ref()
            .is_none_or(|set| set.contains(region))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::identity::AGENT_ID_LEN;

    #[test]
    fn default_profile_has_documented_constants() {
        let p = EffectiveCapabilities::default_profile();
        assert_eq!(p.max_envelopes_per_min, DEFAULT_MAX_ENVELOPES_PER_MIN);
        assert_eq!(p.max_envelope_bytes, DEFAULT_MAX_ENVELOPE_BYTES);
        assert_eq!(p.max_group_size, DEFAULT_MAX_GROUP_SIZE);
        assert!(p.allowed_regions.is_none());
        assert!(p.admin_for.is_empty());
        assert!(p.features.is_empty());
    }

    #[test]
    fn claims_widen_numeric_caps() {
        let eff = EffectiveCapabilities::from_claims(&[
            Capability::MaxGroupSize(100),
            Capability::MaxEnvelopesPerMin(600),
        ]);
        assert_eq!(eff.max_group_size, 100);
        assert_eq!(eff.max_envelopes_per_min, 600);
    }

    #[test]
    fn claims_do_not_tighten_below_default() {
        let eff = EffectiveCapabilities::from_claims(&[Capability::MaxGroupSize(1)]);
        assert_eq!(eff.max_group_size, DEFAULT_MAX_GROUP_SIZE);
    }

    #[test]
    fn region_restriction_narrows_to_set() {
        let regions: BTreeSet<Region> = [Region::Fra].into_iter().collect();
        let eff = EffectiveCapabilities::from_claims(&[Capability::AllowedRegions(regions)]);
        assert!(eff.permits_region(&Region::Fra));
        assert!(!eff.permits_region(&Region::Nyc));
    }

    #[test]
    fn default_profile_permits_every_region() {
        let p = EffectiveCapabilities::default_profile();
        assert!(p.permits_region(&Region::Nyc));
        assert!(p.permits_region(&Region::Sgp));
        assert!(p.permits_region(&Region::Other("tor".to_owned())));
    }

    #[test]
    fn admin_and_features_accumulate() {
        let eff = EffectiveCapabilities::from_claims(&[
            Capability::AdminFor(TenantId::new("acme")),
            Capability::AdminFor(TenantId::new("globex")),
            Capability::Feature(FeatureFlag::EncryptedBackup),
            Capability::Feature(FeatureFlag::Voice),
        ]);
        assert!(eff.admin_for.contains(&TenantId::new("acme")));
        assert!(eff.admin_for.contains(&TenantId::new("globex")));
        assert!(eff.features.contains(&FeatureFlag::EncryptedBackup));
        assert!(eff.features.contains(&FeatureFlag::Voice));
    }

    #[test]
    fn token_postcard_roundtrip() {
        let token = CapabilityToken {
            claims: CapabilityClaims {
                agent_id: AgentId::from_bytes([9u8; AGENT_ID_LEN]),
                tenant_id: Some(TenantId::new("acme")),
                issued_at_ms: 1_700_000_000_000,
                expires_at_ms: 1_700_003_600_000,
                capabilities: vec![
                    Capability::MaxGroupSize(50),
                    Capability::Feature(FeatureFlag::Voice),
                ],
                issuer_key_id: "issuer-v1".to_owned(),
            },
            signature: vec![0xff; 64],
        };
        let bytes = postcard::to_allocvec(&token).unwrap();
        let decoded: CapabilityToken = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(token, decoded);
    }
}
