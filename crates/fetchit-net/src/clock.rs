// SPDX-License-Identifier: AGPL-3.0-only
//
// fetch>it network backend — system-clock skew detection.
// Copyright (C) the fetch>it contributors.

//! Best-effort system-clock skew detection.
//!
//! saorsa-core stamps every protocol message with a UTC timestamp and
//! rejects any whose timestamp is too far from the receiver's clock. A
//! local clock that is wrong *in UTC* therefore makes every peer's
//! identity message look "stale": the DHT routing table never fills and
//! the user sees a misleading `insufficient peers` / "no peers" error
//! with no hint that the real cause is their own clock.
//!
//! This failure is invisible to the user. A machine with a wrong time
//! zone whose clock has been dragged to "look right" shows the correct
//! local time on the taskbar while its UTC clock is hours off — so the
//! one thing a user would naturally check is the one thing that lies.
//! The only reliable test is to compare against an external UTC source,
//! which is what this module does via a single lightweight SNTP query.
//!
//! Pure `std`, no dependencies. Best-effort: any failure (offline,
//! UDP/123 blocked, malformed reply) yields `None`, which callers must
//! treat as "could not determine" — never as "clock is fine".

use std::net::{ToSocketAddrs, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Seconds between the NTP epoch (1900-01-01) and the Unix epoch.
const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

/// Public SNTP servers to try, in order; the first to answer wins.
const NTP_SERVERS: &[&str] = &["time.cloudflare.com:123", "pool.ntp.org:123"];

/// Per-server send/receive timeout.
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Measures the local clock minus true UTC time, in seconds.
///
/// A positive result means the local clock is *ahead* of real time, a
/// negative result *behind*. Returns `None` if no SNTP server could be
/// reached — callers must treat `None` as "unknown", not "fine".
///
/// This performs blocking network I/O; call it from a blocking context
/// (e.g. `tokio::task::spawn_blocking`), not directly on an async task.
pub(crate) fn measure_clock_skew_secs() -> Option<i64> {
    NTP_SERVERS.iter().find_map(|&server| query_one(server))
}

/// Issues one SNTP request and returns the local-vs-true offset, seconds.
fn query_one(server: &str) -> Option<i64> {
    let addr = server.to_socket_addrs().ok()?.next()?;

    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(QUERY_TIMEOUT)).ok()?;
    socket.set_write_timeout(Some(QUERY_TIMEOUT)).ok()?;
    socket.connect(addr).ok()?;

    // SNTP request: 48 bytes, first byte 0x1B (leap 0, version 3,
    // mode 3 = client); every other byte zero.
    let mut request = [0u8; 48];
    request[0] = 0x1B;
    socket.send(&request).ok()?;

    let mut reply = [0u8; 48];
    if socket.recv(&mut reply).ok()? < 48 {
        return None;
    }

    // Transmit Timestamp — integer-seconds part, big-endian, counted
    // from the NTP epoch — sits at bytes 40..44.
    let ntp_secs = u64::from(u32::from_be_bytes([
        reply[40], reply[41], reply[42], reply[43],
    ]));
    let true_unix = ntp_secs.checked_sub(NTP_UNIX_OFFSET)?;
    let local_unix = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();

    // Both are seconds-since-1970 in a sane range; the difference fits i64.
    Some(i64::try_from(local_unix).ok()? - i64::try_from(true_unix).ok()?)
}
