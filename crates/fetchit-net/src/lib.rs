// SPDX-License-Identifier: AGPL-3.0-only
//
// fetch>it network backend — Autonomi-backed `NetworkClient`.
// Copyright (C) the fetch>it contributors.

//! `fetchit-net` — production [`NetworkClient`](fetchit_core::NetworkClient)
//! implementation backed by the Autonomi peer-to-peer network.
//!
//! UI surfaces (CLI, Android, future Tauri shell) construct an
//! [`AutonomiClient`] and pass it to `fetchit-core` as their network
//! backend. This crate is the only place the project links against
//! `ant-core`, `self_encryption`, and friends — keeps the dependency
//! cost out of the engine and out of UI shells that don't need a live
//! connection (tests, fixture inspectors, future WASM viewer).

pub mod client;
mod clock;
pub mod peers;

pub use client::{set_data_home, AutonomiClient};
pub use peers::{parse_bootstrap_peer, DEFAULT_PEERS};
