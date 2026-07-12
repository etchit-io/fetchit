//! `fetchit-bridge-server` — the dedicated `ActivityPub` bridge node.
//!
//! Serves `WebFinger` + actor documents, accepts actor registration, and
//! (in later milestones) handles Follow/Accept and outbox fan-out. Runs
//! as its own binary, structurally isolated from the RAM-only chat
//! relays (`fetchit-relay-server`): the unauthenticated, internet-facing
//! federation surface must not share a process with the load-bearing
//! chat path.

pub mod auth;
pub mod config;
pub mod error;
pub mod metrics;
pub mod ratelimit;
pub mod routes;
pub mod server;
pub mod store;
pub mod store_follow;
