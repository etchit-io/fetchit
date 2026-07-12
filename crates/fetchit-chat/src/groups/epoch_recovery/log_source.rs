//! Production [`CommitSource`] backed by the durable relay group-log.
//!
//! Pulls the records the relay serves for a group (commits for every member
//! plus join-results addressed to this node) via the [`RelayTransport`]
//! group-log passthrough and maps them into the recovery loop's record
//! shape. No relay configured (REST-only / LAN-only) yields no records, so
//! a behind member falls through to the cold pending-join resume rather
//! than reporting a false `Live`.

use std::sync::Arc;

use super::{commit_record_from_wire, CommitRecord, CommitSource};
use crate::error::{ChatError, Result};
use crate::relay_transport::RelayTransport;

/// A [`CommitSource`] that fetches durable group-log records over the
/// relay. The stable group id (64-hex) is decoded to the 32-byte wire
/// [`fetchit_relay_proto::GroupId`] the transport expects.
pub struct LogFetchCommitSource {
    relay: Option<Arc<RelayTransport>>,
}

impl LogFetchCommitSource {
    /// Wrap the client's optional relay transport as a warm commit source.
    #[must_use]
    pub fn new(relay: Option<Arc<RelayTransport>>) -> Self {
        Self { relay }
    }
}

impl CommitSource for LogFetchCommitSource {
    async fn fetch_since(&self, group_id: &str, since_seq: u64) -> Result<Vec<CommitRecord>> {
        let Some(relay) = self.relay.as_ref() else {
            return Ok(Vec::new());
        };
        let mut gid_bytes = [0u8; 32];
        hex::decode_to_slice(group_id, &mut gid_bytes)
            .map_err(|e| ChatError::Invalid(format!("recover: group id hex: {e}")))?;
        let gid = fetchit_relay_proto::GroupId::from_bytes(gid_bytes);
        let wire = relay.log_fetch(gid, since_seq).await?;
        Ok(wire.iter().map(commit_record_from_wire).collect())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::groups::epoch_recovery::CommitRecordKind;
    use base64::Engine as _;
    use fetchit_relay_client::{Signer, StaticKeySigner};
    use fetchit_relay_proto::{GroupId, LogRecordKind, Region};
    use fetchit_relay_server::{AcceptAllVerifier, Server, ServerConfig};
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    async fn start_relay_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = ServerConfig::defaults(addr, Region::Nyc);
        let server = Server::new(cfg).with_verifier(Arc::new(AcceptAllVerifier));
        let (router, _state) = server.router();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        addr
    }

    #[tokio::test]
    async fn fetch_since_maps_relay_records_in_seq_order() {
        let addr = start_relay_server().await;
        let base = url::Url::parse(&format!("http://{addr}/")).unwrap();
        let signer: Arc<dyn Signer + Send + Sync> =
            Arc::new(StaticKeySigner::from_public_key(b"alice-pubkey".to_vec()));
        let transport = RelayTransport::connect(base, signer).await.unwrap();

        let gid_bytes = [0x33u8; 32];
        let gid = GroupId::from_bytes(gid_bytes);
        transport
            .log_append(gid, LogRecordKind::Commit, None, b"c1".to_vec())
            .unwrap();
        transport
            .log_append(gid, LogRecordKind::Commit, None, b"c2".to_vec())
            .unwrap();

        let src = LogFetchCommitSource::new(Some(transport));
        let gid_hex = hex::encode(gid_bytes);
        let recs = src.fetch_since(&gid_hex, 0).await.unwrap();

        assert_eq!(recs.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(recs[0].kind, CommitRecordKind::Commit);
        assert_eq!(
            recs[0].payload_b64,
            base64::engine::general_purpose::STANDARD.encode(b"c1")
        );
    }

    #[tokio::test]
    async fn fetch_since_honours_cursor() {
        let addr = start_relay_server().await;
        let base = url::Url::parse(&format!("http://{addr}/")).unwrap();
        let signer: Arc<dyn Signer + Send + Sync> =
            Arc::new(StaticKeySigner::from_public_key(b"alice-pubkey".to_vec()));
        let transport = RelayTransport::connect(base, signer).await.unwrap();
        let gid_bytes = [0x44u8; 32];
        let gid = GroupId::from_bytes(gid_bytes);
        for p in [b"a".as_slice(), b"b", b"c"] {
            transport
                .log_append(gid, LogRecordKind::Commit, None, p.to_vec())
                .unwrap();
        }
        let src = LogFetchCommitSource::new(Some(transport));
        // since_seq = 2 returns only seq 3.
        let recs = src.fetch_since(&hex::encode(gid_bytes), 2).await.unwrap();
        assert_eq!(recs.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![3]);
    }

    #[tokio::test]
    async fn no_relay_configured_yields_empty() {
        let src = LogFetchCommitSource::new(None);
        let recs = src.fetch_since(&"00".repeat(32), 0).await.unwrap();
        assert!(recs.is_empty(), "no relay -> empty, falls through to cold");
    }

    #[tokio::test]
    async fn bad_group_hex_with_relay_present_is_an_error() {
        let addr = start_relay_server().await;
        let base = url::Url::parse(&format!("http://{addr}/")).unwrap();
        let signer: Arc<dyn Signer + Send + Sync> =
            Arc::new(StaticKeySigner::from_public_key(b"alice-pubkey".to_vec()));
        let transport = RelayTransport::connect(base, signer).await.unwrap();
        let src = LogFetchCommitSource::new(Some(transport));
        // Malformed group id (not 64-hex) is a clean Err, never a panic.
        assert!(src.fetch_since("nothex", 0).await.is_err());
    }
}
