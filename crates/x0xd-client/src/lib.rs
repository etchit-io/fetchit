//! Slim client for a local `x0xd` daemon.
//!
//! Two responsibilities, no chat-stack dependencies:
//!
//! - [`discover_local`] / [`discover_in`] — find the daemon's data
//!   directory and read its `api.port` + `api-token`. Returns a
//!   typed [`DiscoveryError`] so callers can branch on
//!   not-installed-vs-not-running.
//! - [`X0xdSigner`] — implements the [`Signer`] trait by forwarding
//!   ML-DSA-65 operations to `POST /agent/sign`. The local x0xd holds
//!   the private key throughout; this crate never sees it.
//!
//! Designed to be consumed by publishers (etch>it) and chat clients
//! (fetch>it / LIT) alike, so the heavy `saorsa-pqc` keypair impls
//! live downstream in `fetchit-relay-client`, not here.

#![forbid(unsafe_code)]

pub mod discovery;
pub mod error;
pub mod secure;
pub mod signer;
pub mod version;

pub use discovery::{base_url_from_api_port_line, discover_in, discover_local, DaemonEndpoint};
pub use error::{DiscoveryError, X0xdError};
pub use secure::{CreatedGroup, EncryptedFrame, SecureGroupsEndpoint};
pub use signer::{Signer, X0xdSigner};
pub use version::X0xdVersion;
