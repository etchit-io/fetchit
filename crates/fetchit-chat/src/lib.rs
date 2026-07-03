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

pub mod at_rest;
pub mod attachment;
pub mod card;
pub mod chat_crypto;
pub mod chat_identity;
pub mod contacts;
pub mod conversation;
pub mod denylist;
pub mod device_cert;
pub mod discovery;
pub mod error;
pub mod events;
pub mod fabric;
pub mod fedi_identity;
pub mod fedi_resolutions;
pub mod fedi_vault;
pub mod group_invite_uri;
pub mod groups;
pub mod groups_reachability;
pub mod identity;
pub mod lan_direct_transport;
pub mod lan_discovery;
pub mod lan_noise;
pub mod lan_static;
pub mod link_device;
pub mod link_device_enroll;
pub mod link_device_flow;
pub mod link_device_uri;
pub(crate) mod local_signer;
pub mod local_store;
pub mod messages;
pub mod outbox;
pub mod pair;
pub mod pair_record;
pub mod pair_record_v4;
pub mod pair_uri;
pub mod presence;
pub mod profile;
pub mod public;
pub mod recovery_phrase;
pub mod rekey;
pub mod relay_http;
pub mod relay_transport;
pub mod transport;
pub mod x0xd_seed;

mod client;
mod http;
mod members_singleflight;

pub use chat_identity::FetchitIdentity;
pub use client::{
    provision_local_signer_keypair, Client, ClientBuilder, EnsureV2Outcome, FediLookup,
    FediLookupKind, MintOutcome, ProvisionedSignerKey, RelayFailoverEvent,
};
pub use denylist::DenylistCheck;
pub use discovery::{discover_local, DaemonEndpoint};
pub use error::{ChatError, Result};
pub use events::{Event, EventStream};
pub use group_invite_uri::{
    emit_ginvite_uri, parse_ginvite_uri, GinviteUriError, ParsedGinviteUri,
};
pub use client::restore_identity_from_recovery_phrase;
pub use device_cert::{ensure_device_certificate, load_device_certificate};
pub use pair_record_v4::{
    append_device_and_publish, load_pair_record_v4, mint_and_cache_pair_record_v4,
    next_pair_record_v4_revision,
};
pub use link_device_enroll::{
    enroll_confirmed_device, DevicesGroupSink, EnrollOutcome, PendingDevicesGroupSink,
};
pub use local_signer::{
    discard_local_identity, reveal_local_signer_recovery_phrase, reveal_local_signer_seed,
    with_user_key,
};
pub use recovery_phrase::{recovery_phrase_to_seed, seed_to_recovery_phrase};
pub use transport::{Reachability, Router, SendReceipt, Transport};
pub use x0xd_seed::seed_x0xd_agent_key;

/// Re-export of the relay-client's connection-state enum so downstream
/// shells (the desktop bridge) can match on it without taking a direct
/// dependency on `fetchit-relay-client`.
pub use fetchit_relay_client::ConnState as RelayConnState;
