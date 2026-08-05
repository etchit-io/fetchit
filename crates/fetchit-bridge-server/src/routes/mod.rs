//! HTTP route handlers, one module per concern.

pub mod actors;
pub mod follow;
pub mod health;
pub mod inbox;
/// Observability-only helper for [`inbox`]: explains a rejected
/// signature. Not a route, and never part of an accept/reject decision.
mod signature_meta;
pub mod webfinger;
