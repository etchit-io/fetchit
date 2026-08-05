//! HTTP route handlers, one module per concern.

pub mod actors;
pub mod avatar;
pub mod follow;
pub mod health;
pub mod inbox;
/// Signature-header parsing shared by [`inbox`]'s gate (which `keyId`
/// to verify against) and its rejection log. Not a route.
mod signature_meta;
pub mod webfinger;
