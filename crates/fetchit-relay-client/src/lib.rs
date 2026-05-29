//! Client library for connecting to a fetchit relay constellation.

#![forbid(unsafe_code)]
// Underlying tungstenite::Error is unavoidably large; boxing every Result
// per-variant would pollute every fallible API on the crate.
#![allow(clippy::result_large_err)]

pub mod client;
pub mod error;
pub mod outbox;
pub mod region_probe;
pub mod signer;

pub use client::{Client, ClientConfig, ConnState};
pub use error::ClientError;
pub use outbox::Receipt;
pub use region_probe::{probe, ProbeResult};
pub use signer::{MlDsaSigner, Signer, StaticKeySigner, X0xdSigner};
