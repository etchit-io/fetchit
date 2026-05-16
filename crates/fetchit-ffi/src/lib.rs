// SPDX-License-Identifier: AGPL-3.0-only
//
// fetch>it FFI — uniffi bindings over fetchit-core + fetchit-net.
// Copyright (C) the fetch>it contributors.

//! `fetchit-uniffi` — Kotlin/Swift surface for fetch>it.
//!
//! Mirrors etchit's FFI shape: proc-macro `setup_scaffolding!()`,
//! `#[uniffi::export]` on free functions, `#[uniffi::Object]` on the
//! [`Client`] handle, and an FFI-friendly [`RenditionFFI`] enum so
//! Kotlin code can pattern-match on what fetch>it returned.
//!
//! The heavy lifting lives in [`fetchit_core`] (handler engine) and
//! [`fetchit_net`] (Autonomi client). This crate is glue — adapter
//! types, error mapping, and the `cdylib` packaging that ships into
//! `apps/fetchit-android/app/src/main/jniLibs/<arch>/`.

mod error;
mod rendition_ffi;

use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;

use fetchit_core::handlers::{default_registry, extract_entry};
use fetchit_core::{Address, Hint, NetworkClient, RenderContext};
use fetchit_net::{set_data_home as set_data_home_inner, AutonomiClient, DEFAULT_PEERS};

pub use error::FetchitError;
pub use rendition_ffi::{ArchiveEntryFFI, RenditionFFI};

uniffi::setup_scaffolding!();

/// Initialise the native logger.
///
/// On Android this routes `log` crate output to logcat under the
/// `fetchit_ffi` tag. On other platforms it is a no-op so host tests
/// can call it unconditionally. Idempotent — repeated calls are
/// harmless.
#[uniffi::export]
pub fn setup_logger() {
    #[cfg(target_os = "android")]
    {
        use std::sync::Once;
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            // Info, not Debug: `saorsa_transport` / `saorsa_core` emit a
            // per-tick `connection: drive` debug line for every live QUIC
            // connection — at a healthy peer count that floods logcat
            // with thousands of lines a second and burns CPU formatting
            // them. Info keeps the occasional DHT / peer events without
            // the firehose.
            android_logger::init_once(
                android_logger::Config::default()
                    .with_max_level(log::LevelFilter::Info)
                    .with_tag("fetchit_ffi"),
            );
        });
    }
}

/// Set `HOME` and `XDG_DATA_HOME` to `path` if unset.
///
/// Required on Android, where neither variable is set by default —
/// `ant-core`'s internal `data_dir()` resolution will otherwise panic.
/// Pass `context.filesDir.absolutePath` from `Application.onCreate`
/// before any other fetch>it call.
#[uniffi::export]
pub fn set_data_home(path: String) {
    set_data_home_inner(&PathBuf::from(path));
}

/// Bundled production bootstrap peers in `ip:port` shorthand.
///
/// Pass these (or a user override) to [`Client::connect`]. Returning
/// them through the FFI lets Kotlin/Swift surfaces show the defaults
/// in a Settings UI without duplicating the list.
#[must_use]
#[uniffi::export]
pub fn default_peers() -> Vec<String> {
    DEFAULT_PEERS.iter().map(|s| (*s).to_owned()).collect()
}

/// Run handler detection on local bytes — no network.
///
/// Useful for previewing a file the user picked locally, or for unit-
/// testing the handler set from Kotlin without standing up a client.
#[uniffi::export]
pub fn detect(bytes: Vec<u8>) -> Result<RenditionFFI, FetchitError> {
    let rendition = default_registry().render(
        Bytes::from(bytes),
        &Hint::default(),
        &RenderContext::default(),
    )?;
    Ok(rendition.into())
}

/// Read one named entry's decompressed bytes out of a ZIP archive.
///
/// Pure extraction: callers supply the full archive bytes (already
/// fetched / cached by the surface) and an `entry_path` matching one of
/// the [`ArchiveEntryFFI::path`]s returned by [`detect`] /
/// [`Client::fetch_and_render`]. Returns the entry's decompressed bytes;
/// the surface decides what to do with them (render inline, save to
/// disk, hand off to another app).
#[uniffi::export]
pub fn extract_archive_entry(
    archive_bytes: Vec<u8>,
    entry_path: String,
) -> Result<Vec<u8>, FetchitError> {
    Ok(extract_entry(Bytes::from(archive_bytes), &entry_path)?)
}

/// Connected Autonomi client. Construct with [`Client::connect`].
#[derive(uniffi::Object)]
pub struct Client {
    inner: AutonomiClient,
}

#[uniffi::export(async_runtime = "tokio")]
impl Client {
    /// Connect to the network using the supplied bootstrap peers.
    ///
    /// `peers` accepts both `ip:port` shorthand and full multiaddrs.
    /// Pass [`default_peers`] for the standard production set.
    #[uniffi::constructor]
    pub async fn connect(peers: Vec<String>) -> Result<Arc<Self>, FetchitError> {
        let inner = AutonomiClient::connect(&peers).await?;
        Ok(Arc::new(Self { inner }))
    }

    /// Number of currently-connected peers. Suitable for a UI status
    /// indicator.
    pub async fn peer_count(&self) -> u64 {
        self.inner.peer_count().await as u64
    }

    /// Fetch the bytes for `addr` without classification.
    ///
    /// Most callers want [`fetch_and_render`](Self::fetch_and_render)
    /// instead; this method exists for callers that want to apply a
    /// custom handler set or save the raw bytes.
    pub async fn fetch(&self, addr: String) -> Result<Vec<u8>, FetchitError> {
        let parsed: Address = addr.parse()?;
        let bytes = self.inner.fetch(&parsed).await?;
        Ok(bytes.to_vec())
    }

    /// Fetch and render `addr` in one step. The common Android path.
    pub async fn fetch_and_render(&self, addr: String) -> Result<RenditionFFI, FetchitError> {
        let parsed: Address = addr.parse()?;
        let bytes = self.inner.fetch(&parsed).await?;
        let rendition =
            default_registry().render(bytes, &Hint::default(), &RenderContext::default())?;
        Ok(rendition.into())
    }
}
