//! Strongly-typed Rust client for the `x0xd` gossip-network daemon.
//!
//! `x0xd` is a local daemon (default `127.0.0.1:12700`) that exposes a
//! REST + WebSocket API for an agent-to-agent post-quantum encrypted
//! gossip network. This crate is the seam fetch>it uses to drive it —
//! identity, contacts, direct messages, MLS-encrypted groups, presence,
//! and the live event stream — without ever holding a payment wallet
//! or persisted signing key.
//!
//! Entry point is [`Client`]: built from a base URL and a bearer
//! token (both discovered from the daemon's data directory via
//! [`discover_local`]).

#![forbid(unsafe_code)]

pub mod contacts;
pub mod discovery;
pub mod error;
pub mod events;
pub mod groups;
pub mod identity;
pub mod messages;
pub mod presence;

mod client;
mod transport;

pub use client::{Client, ClientBuilder};
pub use discovery::{DaemonEndpoint, discover_local};
pub use error::{ChatError, Result};
pub use events::{Event, EventStream};
