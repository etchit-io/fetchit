//! Backwards-compatible re-export of `x0xd-client`'s discovery API.
//!
//! The discovery logic moved to the slim `x0xd-client` crate so
//! publishers (etch>it) can find x0xd without pulling the chat stack.
//! This module re-exports the same names from the old path so existing
//! callers don't need to change their imports.

pub use x0xd_client::{discover_in, discover_local, DaemonEndpoint, DiscoveryError};
