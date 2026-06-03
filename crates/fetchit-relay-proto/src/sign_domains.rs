//! Domain-separator constants used as signing-input prefixes.
//!
//! Every signed payload on the wire is built from
//! `DOMAIN_SEPARATOR || canonical(payload)` before hashing/signing.
//! The domain separator stops one signing context's bytes from being
//! confused for another (cross-protocol replay defence) and is the
//! load-bearing constant that pins the wire format.
//!
//! These constants are declared here so every consumer (relay
//! server, chat client, desktop wallet, future SDKs) imports the
//! same byte literal. The previous arrangement maintained
//! by-convention copies in `fetchit-chat`, `fetchit-relay-server`,
//! and `etchit-desktop` with a social-contract docstring saying
//! "must byte-match" — adversarial review caught that a future
//! edit in one place would break the wire silently. With the
//! constant living here, compile-time imports turn the social
//! contract into a build-time guarantee.
//!
//! Adding a new domain separator means appending a constant to
//! this module and re-exporting it from `lib.rs`. Never inline a
//! domain string at a call site.

/// Signing-input prefix for the profile manifest record.
///
/// The full signing input is
/// `SIGN_DOMAIN_PROFILE || jcs_canonical(record sans sig)`.
/// The 27-byte length is incidental — the value is the
/// load-bearing piece. Specified verbatim in
/// `docs/profile-manifest-v1.md` § 4.
pub const SIGN_DOMAIN_PROFILE: &[u8] = b"fetchit/profile-manifest/v1";
