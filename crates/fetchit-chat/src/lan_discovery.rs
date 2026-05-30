//! mDNS service discovery for the LAN-direct transport.
//!
//! Discovery surfaces only what's needed to attempt a Noise XX handshake
//! (`agent_id`, ip, port). Everything trust-relevant happens inside
//! Noise against the contact card's ML-DSA pubkey; mDNS announcements
//! are unsigned hints.
//!
//! Service type: `_fetchit-chat._tcp.local.`
//!
//! TXT keys:
//! - `v=1`        schema version
//! - `aid=<64-hex>` the announcer's `agent_id`
//! - `port=<u16>` duplicate of the SRV port (saves a query)

use crate::identity::AgentId;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// DNS-SD service type advertised by the LAN-direct transport.
pub const SERVICE_TYPE: &str = "_fetchit-chat._tcp.local.";

/// Lifetime of a `LanPeerRecord` after its last refresh.
pub const PEER_TTL: Duration = Duration::from_secs(300);

/// TXT key for the announcer's `agent_id` (64-hex).
pub const TXT_KEY_AID: &str = "aid";

/// TXT key for the announcer's TCP port (decimal).
pub const TXT_KEY_PORT: &str = "port";

/// TXT key for the schema version.
pub const TXT_KEY_V: &str = "v";

/// Schema version for v1 records.
pub const TXT_V: &str = "1";

/// What we know about a LAN-announced peer.
#[derive(Clone, Debug)]
pub struct LanPeerRecord {
    /// The peer's `agent_id` parsed from the TXT record.
    pub agent_id: AgentId,
    /// Reachable IP the daemon resolved for the peer.
    pub ip: IpAddr,
    /// TCP port from the SRV record.
    pub port: u16,
    /// When we last saw an announce for this `agent_id`.
    pub last_seen: Instant,
}

/// Thread-safe table of currently-reachable LAN peers indexed by
/// `agent_id`. Stale entries (past [`PEER_TTL`]) are pruned on read.
#[derive(Debug, Default)]
pub struct LanPeerTable {
    inner: Mutex<HashMap<AgentId, LanPeerRecord>>,
}

impl LanPeerTable {
    /// New empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or refresh a peer record.
    pub fn upsert(&self, record: LanPeerRecord) {
        if let Ok(mut g) = self.inner.lock() {
            g.insert(record.agent_id.clone(), record);
        }
    }

    /// Drop a peer record by `agent_id` (called on `ServiceRemoved`).
    pub fn remove(&self, aid: &AgentId) {
        if let Ok(mut g) = self.inner.lock() {
            g.remove(aid);
        }
    }

    /// Look up a peer. Returns `None` if absent or stale.
    #[must_use]
    pub fn lookup(&self, aid: &AgentId) -> Option<LanPeerRecord> {
        let mut g = self.inner.lock().ok()?;
        if let Some(rec) = g.get(aid) {
            if rec.last_seen.elapsed() <= PEER_TTL {
                return Some(rec.clone());
            }
        }
        g.remove(aid);
        None
    }

    /// Snapshot of all fresh entries. Stale entries are pruned in place.
    #[must_use]
    pub fn snapshot(&self) -> Vec<LanPeerRecord> {
        let Ok(mut g) = self.inner.lock() else {
            return Vec::new();
        };
        g.retain(|_, v| v.last_seen.elapsed() <= PEER_TTL);
        g.values().cloned().collect()
    }
}

/// Build the `ServiceInfo` to publish via the daemon.
///
/// `hostname` should end with `.local.` per RFC 6762. `ips` is the set
/// of advertised IPs; the daemon also auto-detects interface addresses.
///
/// # Errors
/// `mdns_sd::Error` for builder-rejection (instance-name length, port
/// out of range, etc).
pub fn build_service_info(
    instance_name: &str,
    hostname: &str,
    ips: &[IpAddr],
    port: u16,
    aid_hex: &str,
) -> Result<ServiceInfo, mdns_sd::Error> {
    let port_str = port.to_string();
    let props: [(&str, &str); 3] = [
        (TXT_KEY_V, TXT_V),
        (TXT_KEY_AID, aid_hex),
        (TXT_KEY_PORT, port_str.as_str()),
    ];
    ServiceInfo::new(SERVICE_TYPE, instance_name, hostname, ips, port, &props[..])
}

/// Spawn a blocking background thread that pumps events from
/// `daemon.browse` into `table`. Returns the join handle so callers can
/// keep it alive for the daemon's lifetime.
///
/// The thread exits cleanly on `ServiceEvent::SearchStopped` (emitted
/// during daemon shutdown).
///
/// # Errors
/// `mdns_sd::Error` if `browse` rejects the service type.
pub fn spawn_browser(
    daemon: &ServiceDaemon,
    table: Arc<LanPeerTable>,
) -> Result<std::thread::JoinHandle<()>, mdns_sd::Error> {
    let rx = daemon.browse(SERVICE_TYPE)?;
    let handle = std::thread::spawn(move || {
        while let Ok(event) = rx.recv() {
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    if let Some(rec) = record_from_resolved(&info) {
                        table.upsert(rec);
                    }
                }
                ServiceEvent::ServiceRemoved(_ty, _fullname) => {
                    // The fullname carries only the short prefix
                    // (`fetchit-<12hex>.<service>`); the full aid lives
                    // in TXT. Removal here is best-effort and the TTL
                    // sweep in `LanPeerTable` is the authoritative
                    // staleness gate.
                }
                ServiceEvent::SearchStopped(_) => break,
                _ => {}
            }
        }
    });
    Ok(handle)
}

fn record_from_resolved(info: &mdns_sd::ResolvedService) -> Option<LanPeerRecord> {
    let aid_hex = info.txt_properties.get_property_val_str(TXT_KEY_AID)?;
    let aid = AgentId::parse(aid_hex.to_owned()).ok()?;
    let ip = info.addresses.iter().next()?.to_ip_addr();
    Some(LanPeerRecord {
        agent_id: aid,
        ip,
        port: info.port,
        last_seen: Instant::now(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn aid(byte: u8) -> AgentId {
        AgentId::parse(hex::encode([byte; 32])).unwrap()
    }

    #[test]
    fn empty_table_lookup_returns_none() {
        let table = LanPeerTable::new();
        assert!(table.lookup(&aid(0)).is_none());
    }

    #[test]
    fn upsert_then_lookup_returns_record() {
        let table = LanPeerTable::new();
        let a = aid(0x11);
        table.upsert(LanPeerRecord {
            agent_id: a.clone(),
            ip: "127.0.0.1".parse().unwrap(),
            port: 4242,
            last_seen: Instant::now(),
        });
        let rec = table.lookup(&a).unwrap();
        assert_eq!(rec.port, 4242);
    }

    #[test]
    fn stale_records_are_dropped_on_lookup() {
        let table = LanPeerTable::new();
        let a = aid(0x22);
        let past = Instant::now()
            .checked_sub(PEER_TTL + Duration::from_secs(1))
            .expect("clock past Unix epoch");
        table.upsert(LanPeerRecord {
            agent_id: a.clone(),
            ip: "127.0.0.1".parse().unwrap(),
            port: 1,
            last_seen: past,
        });
        assert!(table.lookup(&a).is_none());
        assert!(table.snapshot().is_empty());
    }

    #[test]
    fn remove_drops_entry() {
        let table = LanPeerTable::new();
        let a = aid(0x33);
        table.upsert(LanPeerRecord {
            agent_id: a.clone(),
            ip: "127.0.0.1".parse().unwrap(),
            port: 1,
            last_seen: Instant::now(),
        });
        table.remove(&a);
        assert!(table.lookup(&a).is_none());
    }

    #[test]
    fn build_service_info_includes_txt_keys() {
        let aid_hex = "ab".repeat(32);
        let info = build_service_info(
            "fetchit-test",
            "localhost.local.",
            &["127.0.0.1".parse::<IpAddr>().unwrap()],
            45_000,
            &aid_hex,
        )
        .expect("service info");
        assert_eq!(
            info.get_property_val_str(TXT_KEY_AID),
            Some(aid_hex.as_str())
        );
        assert_eq!(info.get_property_val_str(TXT_KEY_V), Some(TXT_V));
        assert_eq!(info.get_property_val_str(TXT_KEY_PORT), Some("45000"));
    }

    #[test]
    #[ignore = "uses multicast — run locally with --ignored"]
    fn announce_and_browse_returns_self_record() {
        let aid_hex = "cd".repeat(32);
        let daemon = ServiceDaemon::new().expect("daemon");
        let table = Arc::new(LanPeerTable::new());
        let _h = spawn_browser(&daemon, table.clone()).expect("browse");

        let info = build_service_info(
            "fetchit-test",
            "localhost.local.",
            &["127.0.0.1".parse::<IpAddr>().unwrap()],
            45_000,
            &aid_hex,
        )
        .expect("service info");
        daemon.register(info).expect("register");

        let deadline = Instant::now() + Duration::from_secs(5);
        let a = AgentId::parse(aid_hex).unwrap();
        while Instant::now() < deadline {
            if let Some(rec) = table.lookup(&a) {
                assert_eq!(rec.port, 45_000);
                let _ = daemon.shutdown();
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = daemon.shutdown();
        panic!("never resolved our own announcement");
    }
}
