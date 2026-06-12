//! Fediverse bridge primitives for fetch>it.
//!
//! This crate implements the **M4 fediverse bridge** outlined in
//! `docs/superpowers/plans/2026-06-07-m4-fediverse-impl-plan.md`. It owns
//! the `ActivityPub` `Actor` representation, the outbound HTTPS POST
//! delivery path with RSA HTTP Signatures (RFC 9421 primary,
//! draft-cavage fallback), the `WebFinger` client, and the inbox-side
//! activity types.
//!
//! ## Boundary
//!
//! `fetchit-fedi` does **not** implement
//! [`fetchit_chat::Transport`](https://docs.rs/fetchit-chat). The plan's
//! [C] decision makes `FediverseTransport::deliver` take a
//! `&PublicPost`, not a `&Envelope`, so DMs cannot cross the bridge at
//! compile time. The chat layer integrates by adding ONE new envelope
//! kind (`PublicPost`) and ONE chat-layer surface that calls into this
//! crate.
//!
//! ## Status
//!
//! Stage 1.1 scaffolding: module shells only. Subsequent commits in the
//! M4 stack fill in the surface per the build sequence in the plan.

pub mod activity;
pub mod actor;
pub mod attestation;
pub mod lookup;
pub mod registry;
pub mod signature;
pub mod signature_cache;
pub mod signature_cavage;
pub mod ssrf;
pub mod transport;
pub mod webfinger;

pub use activity::PublicPost;
pub use webfinger::{parse_mention, resolve_handle, ParsedHandle, WebFingerError};
