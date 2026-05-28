//! Trust service: report queue + signed denylist publisher.
//!
//! Clients (the desktop reader, mobile reader, chat clients, the
//! relay) poll the published denylists and apply them locally. The
//! relay refuses to mint bearer tokens for denylisted agent ids. The
//! reader refuses to render denylisted addresses. Reports submitted to
//! `/v1/report` queue for moderator review, and accepted ones update
//! the published denylist.

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod server;
pub mod signer;
pub mod storage;
pub mod types;

pub use config::ServerConfig;
pub use error::TrustError;
pub use server::Server;
pub use signer::IssuerSigner;
pub use storage::Storage;
pub use types::{DenylistEntry, DenylistResponse, EntryKind, Report, ReportKind, TargetIdentity};
