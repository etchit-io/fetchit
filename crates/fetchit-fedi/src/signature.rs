//! HTTP Signature signer + key material.
//!
//! Plan Stage 2.1a lands the RFC 9421 primary path; Stage 2.1b adds the
//! draft-cavage fallback plus a 24h per-instance signing-scheme cache.
//! Only the RSA-2048 path is implemented — per plan decision [III] there
//! is no per-POST ML-DSA cosig; the Actor JSON-LD attestation is the
//! authoritative PQ binding.
