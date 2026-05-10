// SPDX-License-Identifier: GPL-3.0-only
//
// fetch>it core — universal read-only viewer engine for the Autonomi network.
// Copyright (C) the fetch>it contributors.

//! # `fetchit-core`
//!
//! The engine half of fetch>it. Given an Autonomi [`Address`], a
//! [`NetworkClient`] fetches the bytes and a [`HandlerRegistry`] turns
//! them into a typed [`Rendition`] that UI shells can display.
//!
//! ```text
//!     ┌──────────────┐   addr     ┌──────────────┐  bytes  ┌──────────────────┐
//!     │ caller (UI)  │ ─────────▶ │ NetworkClient│ ──────▶ │ HandlerRegistry  │
//!     └──────────────┘            └──────────────┘         └────────┬─────────┘
//!                                                                   │ Rendition
//!                                                                   ▼
//!                                                          ┌──────────────────┐
//!                                                          │ caller (UI)      │
//!                                                          │ dispatches on    │
//!                                                          │ Rendition variant│
//!                                                          └──────────────────┘
//! ```
//!
//! ## Stateless
//!
//! `fetchit-core` does not persist anything. No on-disk caches, no
//! `dirs::data_dir()`, no `HOME` reads. Network access goes through the
//! [`NetworkClient`] trait so the surface layer chooses what backs it.
//!
//! ## Adding a content type
//!
//! Implement [`ContentHandler`], register it via
//! [`HandlerRegistry::register`]. See `docs/HANDLER-AUTHORS.md`.

pub mod address;
pub mod error;
pub mod handler;
pub mod handlers;
pub mod network;
pub mod registry;

pub use address::Address;
pub use error::{Error, Result};
pub use handler::{Confidence, ContentHandler, Hint, RenderContext, Rendition};
pub use network::NetworkClient;
pub use registry::HandlerRegistry;
