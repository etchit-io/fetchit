//! Actor identity + Mastodon-compatible JSON-LD representation.
//!
//! Fills out in Stage 1.2 (`ActorIdentity` mint/load) and Stage 1.3
//! (`Actor` JSON-LD round-trip). The ML-DSA-65 attestation over the
//! RSA-2048 pubkey is the authoritative PQ binding per the plan's
//! decision [III] — there is no per-POST ML-DSA cosig.
