//! `Transport` impl that delivers chat envelopes over the LAN via a
//! Noise XX channel established by ML-DSA-signed peer discovery.
//!
//! Trust model: `reachability` returns `IfReachable` **only** when (a)
//! the peer's `agent_id` appears in [`crate::lan_discovery::LanPeerTable`]
//! (fresh mDNS announce) and (b) the contact-pubkey lookup returns the
//! peer's ML-DSA-65 public key (i.e., the peer is already a known
//! contact from a previous share-URI import). A LAN announcement on its
//! own never promotes a stranger to dial-target.
//!
//! Send + listener wiring (TCP connect, Noise handshake, framed
//! `TransitEnvelope` forwarding) lands in a follow-up step — this
//! module owns the trait surface and the reachability gate.

use crate::error::{ChatError, Result};
use crate::identity::AgentId;
use crate::lan_discovery::LanPeerTable;
use crate::lan_static::LanStaticIdentity;
use crate::transport::{
    InboundEnvelope, OutboundEnvelope, Reachability, SendReceipt, Transport,
};
use async_trait::async_trait;
use fetchit_relay_client::Signer;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use tokio::sync::mpsc;

/// Stable name returned by [`Transport::name`].
pub const TRANSPORT_NAME: &str = "lan-direct";

/// Closure that resolves a peer `agent_id` to its ML-DSA-65 public key
/// (as stored on the local contact card). `None` for unknown peers —
/// callers reject those before any Noise handshake runs.
pub type ContactPubkeyLookup =
    Arc<dyn Fn(&AgentId) -> Option<Vec<u8>> + Send + Sync>;

/// LAN-direct chat transport. See module-level docs.
pub struct LanDirectTransport {
    local_agent_id: AgentId,
    local_static: Arc<LanStaticIdentity>,
    signer: Arc<dyn Signer>,
    table: Arc<LanPeerTable>,
    contact_pubkey_lookup: ContactPubkeyLookup,
    inbound_rx: StdMutex<Option<mpsc::UnboundedReceiver<InboundEnvelope>>>,
}

impl LanDirectTransport {
    /// Bare construction for unit-testing the reachability gate. The
    /// inbound mpsc is created here and dropped on `take_inbound`. The
    /// listener-driven side (which spawns the accept loop and feeds
    /// `inbound_tx`) lands in the next step.
    #[must_use]
    pub fn new(
        local_agent_id: AgentId,
        local_static: Arc<LanStaticIdentity>,
        signer: Arc<dyn Signer>,
        table: Arc<LanPeerTable>,
        contact_pubkey_lookup: ContactPubkeyLookup,
    ) -> Arc<Self> {
        let (_tx, rx) = mpsc::unbounded_channel::<InboundEnvelope>();
        Arc::new(Self {
            local_agent_id,
            local_static,
            signer,
            table,
            contact_pubkey_lookup,
            inbound_rx: StdMutex::new(Some(rx)),
        })
    }

    /// Borrow the local agent id this transport advertises and binds.
    #[must_use]
    pub fn local_agent_id(&self) -> &AgentId {
        &self.local_agent_id
    }

    /// Borrow the local Noise static identity (used by the listener
    /// half once it lands).
    #[must_use]
    pub fn local_static(&self) -> &Arc<LanStaticIdentity> {
        &self.local_static
    }

    /// Borrow the contact-pubkey lookup closure (visible to the
    /// listener half).
    #[must_use]
    pub fn contact_pubkey_lookup(&self) -> &ContactPubkeyLookup {
        &self.contact_pubkey_lookup
    }

    /// Borrow the LAN peer table (visible to the listener half).
    #[must_use]
    pub fn peer_table(&self) -> &Arc<LanPeerTable> {
        &self.table
    }

    /// Borrow the signer (visible to the listener half).
    #[must_use]
    pub fn signer(&self) -> &Arc<dyn Signer> {
        &self.signer
    }
}

#[async_trait]
impl Transport for LanDirectTransport {
    fn name(&self) -> &'static str {
        TRANSPORT_NAME
    }

    fn reachability(&self, to: &AgentId) -> Reachability {
        if self.table.lookup(to).is_none() {
            return Reachability::No;
        }
        if (self.contact_pubkey_lookup)(to).is_none() {
            return Reachability::No;
        }
        Reachability::IfReachable
    }

    async fn send(&self, _to: &AgentId, _envelope: OutboundEnvelope) -> Result<SendReceipt> {
        Err(ChatError::MessageTransport(
            "lan-direct send not yet wired".into(),
        ))
    }

    fn take_inbound(&self) -> Option<mpsc::UnboundedReceiver<InboundEnvelope>> {
        self.inbound_rx.lock().ok().and_then(|mut g| g.take())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::at_rest::{fresh_argon_salt, kdf_id_argon2, MasterKey, MasterKeySource};
    use crate::lan_discovery::{LanPeerRecord, LanPeerTable};
    use fetchit_relay_client::MlDsaSigner;
    use std::time::Instant;
    use tempfile::tempdir;

    fn aid(byte: u8) -> AgentId {
        AgentId::parse(hex::encode([byte; 32])).unwrap()
    }

    fn make_transport(
        local_aid: AgentId,
        table: Arc<LanPeerTable>,
        lookup: ContactPubkeyLookup,
    ) -> Arc<LanDirectTransport> {
        let dir = tempdir().unwrap();
        let salt = fresh_argon_salt();
        let master =
            MasterKey::resolve(&MasterKeySource::Passphrase("p".into()), Some(&salt)).unwrap();
        let local_static = Arc::new(
            LanStaticIdentity::load_or_create(
                dir.path(),
                &master,
                &local_aid.0,
                kdf_id_argon2(),
                Some(&salt),
            )
            .unwrap(),
        );
        let signer = Arc::new(MlDsaSigner::generate().unwrap()) as Arc<dyn Signer>;
        LanDirectTransport::new(local_aid, local_static, signer, table, lookup)
    }

    #[test]
    fn name_is_lan_direct() {
        let table = Arc::new(LanPeerTable::new());
        let lookup: ContactPubkeyLookup =
            Arc::new(|_a: &AgentId| -> Option<Vec<u8>> { None });
        let t = make_transport(aid(0x01), table, lookup);
        assert_eq!(t.name(), "lan-direct");
    }

    #[test]
    fn reachability_no_when_peer_not_in_lan_table() {
        let table = Arc::new(LanPeerTable::new());
        // Lookup would succeed, but the LAN table is empty.
        let lookup: ContactPubkeyLookup =
            Arc::new(|_a: &AgentId| -> Option<Vec<u8>> { Some(vec![0xaa; 32]) });
        let t = make_transport(aid(0x01), table, lookup);
        assert_eq!(t.reachability(&aid(0xff)), Reachability::No);
    }

    #[test]
    fn reachability_no_when_peer_not_in_contact_store() {
        let table = Arc::new(LanPeerTable::new());
        let peer = aid(0xee);
        table.upsert(LanPeerRecord {
            agent_id: peer.clone(),
            ip: "127.0.0.1".parse().unwrap(),
            port: 4242,
            last_seen: Instant::now(),
        });
        // Empty contact store — never trust strangers on the LAN.
        let lookup: ContactPubkeyLookup =
            Arc::new(|_a: &AgentId| -> Option<Vec<u8>> { None });
        let t = make_transport(aid(0x01), table, lookup);
        assert_eq!(t.reachability(&peer), Reachability::No);
    }

    #[test]
    fn reachability_if_reachable_when_both_present() {
        let table = Arc::new(LanPeerTable::new());
        let peer = aid(0xdd);
        table.upsert(LanPeerRecord {
            agent_id: peer.clone(),
            ip: "127.0.0.1".parse().unwrap(),
            port: 4242,
            last_seen: Instant::now(),
        });
        let peer_for_lookup = peer.clone();
        let lookup: ContactPubkeyLookup = Arc::new(move |q: &AgentId| -> Option<Vec<u8>> {
            if *q == peer_for_lookup {
                Some(vec![0xab; 64])
            } else {
                None
            }
        });
        let t = make_transport(aid(0x01), table, lookup);
        assert_eq!(t.reachability(&peer), Reachability::IfReachable);
    }
}
