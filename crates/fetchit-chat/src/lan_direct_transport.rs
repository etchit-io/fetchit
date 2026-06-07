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
//! Wire shape per connection:
//! 1. Initiator sends an unauthenticated 32-byte header carrying its
//!    `agent_id`. Responder reads it and folds it into the Noise
//!    prologue alongside its own `agent_id`.
//! 2. Noise XX runs over the same socket with msg2 + msg3 carrying the
//!    binding payload (see [`crate::lan_noise`]).
//! 3. After the handshake, the initiator writes one or more framed
//!    [`fetchit_relay_proto::TransitEnvelope`]s through the cipherstate.
//!    The responder reads frames until the connection closes and pumps
//!    each one onto the transport's inbound mpsc as an
//!    [`InboundEnvelope`].
//!
//! Sealed-only send contract: every `send` MUST carry a prebuilt sealed
//! `TransitEnvelope` on `OutboundEnvelope.transit`. The conversation /
//! group layer is the only sanctioned producer. Callers that pass
//! `transit: None` get [`ChatError::SealedRequired`] before the
//! transport touches the network — the legacy v1 fabricated escape
//! hatch has been removed for parity with
//! [`crate::relay_transport::RelayTransport`].

use crate::error::{ChatError, Result};
use crate::identity::AgentId;
use crate::lan_discovery::LanPeerTable;
use crate::lan_noise::{read_app_frame, run_initiator_bound, run_responder_bound, write_app_frame};
use crate::lan_static::LanStaticIdentity;
use crate::transport::{
    InboundEnvelope, OutboundEnvelope, OutboundKind, Reachability, SendReceipt, Transport,
};
use async_trait::async_trait;
use fetchit_relay_client::Signer;
use fetchit_relay_proto::{EnvelopeKind as RelayKind, TransitEnvelope};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};

/// Stable name returned by [`Transport::name`].
pub const TRANSPORT_NAME: &str = "lan-direct";

/// Prologue prefix bytes (precede the two `agent_id`s in the
/// committed handshake hash).
pub const PROLOGUE_PREFIX: &[u8] = b"fetchit-lan-v1";

/// Maximum inbound handshakes in flight process-wide before
/// `accept` starts dropping new connections. Conservative v1 cap.
pub const INBOUND_HANDSHAKE_CAP: usize = 32;

/// Per-handshake budget for the LAN-direct transport: covers TCP
/// connect on outbound, plus the Noise-XX handshake itself, on both
/// sides. An unresponsive peer cannot stall a slot longer than this.
const LAN_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Closure that resolves a peer `agent_id` to its ML-DSA-65 public key
/// (as stored on the local contact card). `None` for unknown peers —
/// callers reject those before any Noise handshake runs.
pub type ContactPubkeyLookup = Arc<dyn Fn(&AgentId) -> Option<Vec<u8>> + Send + Sync>;

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
    /// Bind a TCP listener on `bind`, spawn the accept loop, and return
    /// the configured transport plus the actual bound `SocketAddr` (so
    /// callers binding `0.0.0.0:0` can publish the assigned port via
    /// mDNS).
    ///
    /// The accept loop runs as a tokio task for the lifetime of the
    /// returned `Arc<Self>`. Inbound frames pump onto a channel exposed
    /// via [`Transport::take_inbound`].
    ///
    /// # Errors
    /// I/O failure binding the listener.
    pub async fn start(
        local_agent_id: AgentId,
        local_static: Arc<LanStaticIdentity>,
        signer: Arc<dyn Signer>,
        table: Arc<LanPeerTable>,
        contact_pubkey_lookup: ContactPubkeyLookup,
        bind: SocketAddr,
    ) -> Result<(Arc<Self>, SocketAddr)> {
        let listener = TcpListener::bind(bind).await.map_err(io_err)?;
        let bound = listener.local_addr().map_err(io_err)?;
        let (tx, rx) = mpsc::unbounded_channel::<InboundEnvelope>();
        let transport = Arc::new(Self {
            local_agent_id: local_agent_id.clone(),
            local_static: local_static.clone(),
            signer: signer.clone(),
            table,
            contact_pubkey_lookup: contact_pubkey_lookup.clone(),
            inbound_rx: StdMutex::new(Some(rx)),
        });
        spawn_accept_loop(
            listener,
            tx,
            local_agent_id,
            local_static,
            signer,
            contact_pubkey_lookup,
        );
        Ok((transport, bound))
    }

    /// Borrow the local agent id this transport advertises and binds.
    #[must_use]
    pub fn local_agent_id(&self) -> &AgentId {
        &self.local_agent_id
    }

    /// Borrow the local Noise static identity.
    #[must_use]
    pub fn local_static(&self) -> &Arc<LanStaticIdentity> {
        &self.local_static
    }

    /// Borrow the contact-pubkey lookup closure.
    #[must_use]
    pub fn contact_pubkey_lookup(&self) -> &ContactPubkeyLookup {
        &self.contact_pubkey_lookup
    }

    /// Borrow the LAN peer table.
    #[must_use]
    pub fn peer_table(&self) -> &Arc<LanPeerTable> {
        &self.table
    }

    /// Borrow the signer.
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

    async fn send(
        &self,
        to: &AgentId,
        envelope: OutboundEnvelope,
        hints: Option<&crate::card::RendezvousHintsV1>,
    ) -> Result<SendReceipt> {
        // LAN-direct routes via mDNS-discovered IP:port, not WS relays;
        // advertised relay hints are irrelevant here.
        let _ = hints;
        // Sealed-required guard ahead of any network I/O: a buggy
        // caller must not be able to spend a TCP connect + Noise XX
        // handshake on a wire-shape that would be refused at the last
        // step anyway.
        let transit = materialise_transit(&self.local_agent_id, &envelope)?;

        let rec = self
            .table
            .lookup(to)
            .ok_or_else(|| ChatError::MessageTransport(format!("lan peer {to:?} stale")))?;

        // Bound TCP connect: an unrouted/silent peer must not stall
        // the caller. Mirrored on the inbound side via the same const.
        let mut stream = tokio::time::timeout(
            LAN_HANDSHAKE_TIMEOUT,
            TcpStream::connect((rec.ip, rec.port)),
        )
        .await
        .map_err(|_| ChatError::MessageTransport("lan handshake timeout".into()))?
        .map_err(io_err)?;
        let local_aid_bytes = agent_id_bytes(&self.local_agent_id)?;
        let peer_aid_bytes = agent_id_bytes(to)?;
        // Header: unauthenticated initiator aid hint so the responder
        // can fold it into its prologue.
        stream.write_all(&local_aid_bytes).await.map_err(io_err)?;

        let prologue = make_prologue(&local_aid_bytes, &peer_aid_bytes);
        let signer = self.signer.clone();
        let lookup = self.contact_pubkey_lookup.clone();
        let static_pub = *self.local_static.x25519_public();
        let static_sec = *self.local_static.x25519_secret();
        let created_at = self.local_static.created_at_ms();

        let (mut ts, _verified) = tokio::time::timeout(
            LAN_HANDSHAKE_TIMEOUT,
            run_initiator_bound(
                &mut stream,
                &prologue,
                &static_sec,
                &local_aid_bytes,
                &static_pub,
                created_at,
                sign_blob(signer),
                &move |q: &[u8; 32]| {
                    let aid = AgentId::parse(hex::encode(q)).ok()?;
                    lookup(&aid)
                },
            ),
        )
        .await
        .map_err(|_| ChatError::MessageTransport("lan handshake timeout".into()))??;

        let bytes = postcard::to_allocvec(&transit)
            .map_err(|e| ChatError::Invalid(format!("transit encode: {e}")))?;
        write_app_frame(&mut stream, &mut ts, &bytes).await?;
        // Half-close — signals "no more frames from this side". Best
        // effort; not all platforms honour shutdown(Write).
        let _ = stream.shutdown().await;

        Ok(SendReceipt {
            accepted_at_ms: now_ms(),
            message_id: None,
            transport_name: TRANSPORT_NAME,
        })
    }

    fn take_inbound(&self) -> Option<mpsc::UnboundedReceiver<InboundEnvelope>> {
        self.inbound_rx.lock().ok().and_then(|mut g| g.take())
    }
}

fn spawn_accept_loop(
    listener: TcpListener,
    tx: mpsc::UnboundedSender<InboundEnvelope>,
    local_agent_id: AgentId,
    local_static: Arc<LanStaticIdentity>,
    signer: Arc<dyn Signer>,
    contact_pubkey_lookup: ContactPubkeyLookup,
) {
    let permits = Arc::new(Semaphore::new(INBOUND_HANDSHAKE_CAP));
    tokio::spawn(async move {
        loop {
            let Ok((stream, _peer_addr)) = listener.accept().await else {
                break;
            };
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                // Capacity exceeded — drop the connection cold.
                drop(stream);
                continue;
            };
            let tx = tx.clone();
            let local_aid = local_agent_id.clone();
            let local_static = local_static.clone();
            let signer = signer.clone();
            let lookup = contact_pubkey_lookup.clone();
            tokio::spawn(async move {
                let _permit = permit;
                // Bound the handshake — without this, a slow peer can
                // pin a semaphore slot forever and a flood of 32 stalls
                // wedges the listener entirely.
                match tokio::time::timeout(
                    LAN_HANDSHAKE_TIMEOUT,
                    handle_inbound_conn(stream, tx, local_aid, local_static, signer, lookup),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => log::debug!("lan-direct inbound conn ended: {e}"),
                    Err(_) => log::warn!("lan-direct inbound handshake timed out"),
                }
            });
        }
    });
}

async fn handle_inbound_conn(
    mut stream: TcpStream,
    tx: mpsc::UnboundedSender<InboundEnvelope>,
    local_agent_id: AgentId,
    local_static: Arc<LanStaticIdentity>,
    signer: Arc<dyn Signer>,
    contact_pubkey_lookup: ContactPubkeyLookup,
) -> Result<()> {
    let mut init_aid_bytes = [0u8; 32];
    stream
        .read_exact(&mut init_aid_bytes)
        .await
        .map_err(io_err)?;

    let my_aid_bytes = agent_id_bytes(&local_agent_id)?;
    let prologue = make_prologue(&init_aid_bytes, &my_aid_bytes);
    let static_pub = *local_static.x25519_public();
    let static_sec = *local_static.x25519_secret();
    let created_at = local_static.created_at_ms();

    let lookup_for_handshake = contact_pubkey_lookup.clone();
    let (mut ts, verified) = run_responder_bound(
        &mut stream,
        &prologue,
        &static_sec,
        &my_aid_bytes,
        &static_pub,
        created_at,
        sign_blob(signer),
        &move |q: &[u8; 32]| {
            let aid = AgentId::parse(hex::encode(q)).ok()?;
            lookup_for_handshake(&aid)
        },
    )
    .await?;
    let verified_aid = AgentId::parse(hex::encode(verified.agent_id))?;

    loop {
        let bytes = match read_app_frame(&mut stream, &mut ts).await {
            Ok(b) => b,
            Err(ChatError::Io(_)) => return Ok(()), // peer closed
            Err(e) => return Err(e),
        };
        let transit: TransitEnvelope = postcard::from_bytes(&bytes)
            .map_err(|e| ChatError::Invalid(format!("transit decode: {e}")))?;
        // The TransitEnvelope is encrypted+framed but its sender field
        // is plaintext-from-the-peer: bind it to the identity the
        // handshake actually proved, or downstream sees a spoofed sender.
        if transit.sender_agent_id.as_bytes() != &verified.agent_id {
            return Err(ChatError::Invalid(format!(
                "transit sender_agent_id mismatch: claimed {}, authenticated {}",
                hex::encode(transit.sender_agent_id.as_bytes()),
                verified_aid.0
            )));
        }
        let Some(inbound) = inbound_envelope_from_transit(verified_aid.clone(), transit) else {
            // Unknown forward-compat kind from a newer sender — drop here.
            continue;
        };
        if tx.send(inbound).is_err() {
            return Ok(());
        }
    }
}

fn inbound_envelope_from_transit(from: AgentId, env: TransitEnvelope) -> Option<InboundEnvelope> {
    let kind = match env.kind {
        // X0xdGroupMetadataEvent: M2.5 bridge variant — wire-shape
        // carry only at C1; the dispatcher in peer.rs discriminates
        // on `transit.kind` and routes to the local /publish path in
        // C3. Rides the Dm shape because the chat-layer routing
        // predicate doesn't yet model bridge events.
        RelayKind::Dm
        | RelayKind::AdminEvent
        | RelayKind::X0xdGroupMetadataEvent
        | RelayKind::WelcomeBlobRequest
        | RelayKind::WelcomeBlobResponse => OutboundKind::Dm,
        // PrivateGroupChat rides the same inbound shape as GroupChat —
        // downstream `is_private_group_envelope` discriminates the two.
        RelayKind::GroupChat | RelayKind::PrivateGroupChat | RelayKind::DeliveryReceipt => {
            OutboundKind::Group {
                group_id: env
                    .group_id
                    .map(|g| hex::encode(g.as_bytes()))
                    .unwrap_or_default(),
            }
        }
        // Forward-compat: an envelope from a newer peer carrying a
        // kind this proto doesn't recognise. We drop it at the
        // transport layer — the chat layer has no semantics to map
        // it to. Returning None lets the pump skip cleanly without
        // breaking subsequent envelopes.
        RelayKind::Unknown(disc) => {
            log::warn!("lan-direct inbound: dropping envelope with unknown kind disc={disc}");
            return None;
        }
        // M4 Stage 5.1-proto wire DISC reservation. PublicPost
        // (fediverse-bridge inbound activity) has no chat-layer
        // semantics on the LAN-direct path — drop with a log warn
        // until Stage 5.3 wires the public-feed handler dispatch.
        // LAN-direct never carries a PublicPost in production today
        // (the inbox endpoint is the only producer); the arm exists
        // to keep the match exhaustive.
        RelayKind::PublicPost => {
            log::warn!(
                "lan-direct inbound: dropping PublicPost — no chat-layer route until Stage 5.3"
            );
            return None;
        }
    };
    Some(InboundEnvelope {
        kind,
        from,
        payload: env.ciphertext.clone(),
        timestamp_ms: env.timestamp_ms,
        transport_name: TRANSPORT_NAME,
        transit: Some(env),
    })
}

fn materialise_transit(
    local_agent_id: &AgentId,
    envelope: &OutboundEnvelope,
) -> Result<TransitEnvelope> {
    let local_aid = agent_id_bytes(local_agent_id)?;
    // Sealed-only post-M2. The conversation/group layer is the only
    // sanctioned producer of a `TransitEnvelope` for this transport;
    // the v1 fabricated escape hatch has been removed for parity with
    // `RelayTransport::send`. A buggy or wrong-version caller surfaces
    // `SealedRequired` here instead of silently emitting an unsealed
    // wire shape.
    let prebuilt = envelope.transit.as_ref().ok_or(ChatError::SealedRequired {
        caller: "LanDirectTransport::send",
    })?;
    if prebuilt.sender_agent_id.as_bytes() != &local_aid {
        return Err(ChatError::Invalid(format!(
            "prebuilt envelope sender_agent_id mismatch: claimed {}, local {}",
            hex::encode(prebuilt.sender_agent_id.as_bytes()),
            local_agent_id.0
        )));
    }
    Ok(prebuilt.clone())
}

fn make_prologue(init_aid: &[u8; 32], resp_aid: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PROLOGUE_PREFIX.len() + 64);
    out.extend_from_slice(PROLOGUE_PREFIX);
    out.extend_from_slice(init_aid);
    out.extend_from_slice(resp_aid);
    out
}

type SignFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send>>;

fn sign_blob(signer: Arc<dyn Signer>) -> impl FnOnce(Vec<u8>) -> SignFuture + Send {
    move |bytes| {
        Box::pin(async move {
            signer
                .sign(&bytes)
                .await
                .map_err(|e| ChatError::Invalid(format!("signer: {e}")))
        })
    }
}

fn agent_id_bytes(id: &AgentId) -> Result<[u8; 32]> {
    parse_hex_32(&id.0).map_err(|e| ChatError::Invalid(format!("agent id: {e}")))
}

fn parse_hex_32(s: &str) -> std::result::Result<[u8; 32], String> {
    let raw = hex::decode(s).map_err(|e| e.to_string())?;
    raw.try_into()
        .map_err(|v: Vec<u8>| format!("expected 32 bytes, got {}", v.len()))
}

#[allow(clippy::needless_pass_by_value)] // used as a `.map_err(io_err)` callback
fn io_err(e: std::io::Error) -> ChatError {
    ChatError::MessageTransport(format!("lan-direct io: {e}"))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names,
    clippy::too_many_lines
)]
mod tests {
    use super::*;
    use crate::at_rest::{fresh_argon_salt, kdf_id_argon2, MasterKey, MasterKeySource};
    use crate::lan_discovery::{LanPeerRecord, LanPeerTable};
    use fetchit_relay_client::MlDsaSigner;
    use fetchit_relay_proto::{AgentId as RelayAgentId, MachineId, WIRE_VERSION};
    use std::time::Instant;
    use tempfile::tempdir;
    use zeroize::Zeroizing;

    fn aid(byte: u8) -> AgentId {
        AgentId::parse(hex::encode([byte; 32])).unwrap()
    }

    /// Build an `OutboundEnvelope` with a sealed-enough prebuilt
    /// `TransitEnvelope`. The conversation/group layer is the real
    /// producer in production; this stub is just enough to satisfy the
    /// sealed-required guard and the sender-binding check.
    fn sealed_outbound_dm(local_aid: &AgentId, payload: Vec<u8>, ts_ms: u64) -> OutboundEnvelope {
        let local_bytes = agent_id_bytes(local_aid).unwrap();
        let transit = TransitEnvelope {
            version: WIRE_VERSION,
            kind: RelayKind::Dm,
            group_id: None,
            tenant_id: None,
            sender_agent_id: RelayAgentId::from_bytes(local_bytes),
            sender_machine_id: MachineId::from_bytes([0u8; 32]),
            timestamp_ms: ts_ms,
            epoch: 0,
            ciphertext: payload.clone(),
            nonce: Vec::new(),
            kem_ciphertext: Vec::new(),
            sender_signature: Vec::new(),
        };
        OutboundEnvelope {
            kind: OutboundKind::Dm,
            from_machine_id: None,
            payload,
            timestamp_ms: ts_ms,
            transit: Some(transit),
        }
    }

    fn fresh_static(aid_hex: &str) -> Arc<LanStaticIdentity> {
        let dir = tempdir().unwrap();
        let salt = fresh_argon_salt();
        let master = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("p".into())),
            Some(&salt),
        )
        .unwrap();
        Arc::new(
            LanStaticIdentity::load_or_create(
                dir.path(),
                &master,
                aid_hex,
                kdf_id_argon2(),
                Some(&salt),
            )
            .unwrap(),
        )
    }

    fn skeleton_transport(
        local_aid: AgentId,
        table: Arc<LanPeerTable>,
        lookup: ContactPubkeyLookup,
    ) -> Arc<LanDirectTransport> {
        let signer = Arc::new(MlDsaSigner::generate().unwrap()) as Arc<dyn Signer>;
        let local_static = fresh_static(&local_aid.0);
        Arc::new(LanDirectTransport {
            local_agent_id: local_aid,
            local_static,
            signer,
            table,
            contact_pubkey_lookup: lookup,
            inbound_rx: StdMutex::new(Some(mpsc::unbounded_channel().1)),
        })
    }

    #[test]
    fn name_is_lan_direct() {
        let table = Arc::new(LanPeerTable::new());
        let lookup: ContactPubkeyLookup = Arc::new(|_a: &AgentId| -> Option<Vec<u8>> { None });
        let t = skeleton_transport(aid(0x01), table, lookup);
        assert_eq!(t.name(), "lan-direct");
    }

    #[test]
    fn reachability_no_when_peer_not_in_lan_table() {
        let table = Arc::new(LanPeerTable::new());
        let lookup: ContactPubkeyLookup =
            Arc::new(|_a: &AgentId| -> Option<Vec<u8>> { Some(vec![0xaa; 32]) });
        let t = skeleton_transport(aid(0x01), table, lookup);
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
        let lookup: ContactPubkeyLookup = Arc::new(|_a: &AgentId| -> Option<Vec<u8>> { None });
        let t = skeleton_transport(aid(0x01), table, lookup);
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
        let t = skeleton_transport(aid(0x01), table, lookup);
        assert_eq!(t.reachability(&peer), Reachability::IfReachable);
    }

    #[tokio::test]
    async fn send_completes_and_responder_decodes_transit() {
        // Two transports on 127.0.0.1, cross-pointing. Send A → B and
        // assert B's inbound mpsc yields the same TransitEnvelope.
        let aid_a = aid(0x11);
        let aid_b = aid(0x22);

        let signer_a = Arc::new(MlDsaSigner::generate().unwrap());
        let signer_b = Arc::new(MlDsaSigner::generate().unwrap());
        let pk_a = signer_a.public_key();
        let pk_b = signer_b.public_key();

        let lookup_a: ContactPubkeyLookup = {
            let aid_b = aid_b.clone();
            let pk_b = pk_b.clone();
            Arc::new(move |q: &AgentId| {
                if *q == aid_b {
                    Some(pk_b.clone())
                } else {
                    None
                }
            })
        };
        let lookup_b: ContactPubkeyLookup = {
            let aid_a = aid_a.clone();
            let pk_a = pk_a.clone();
            Arc::new(move |q: &AgentId| {
                if *q == aid_a {
                    Some(pk_a.clone())
                } else {
                    None
                }
            })
        };

        let table_a = Arc::new(LanPeerTable::new());
        let table_b = Arc::new(LanPeerTable::new());

        let static_a = fresh_static(&aid_a.0);
        let static_b = fresh_static(&aid_b.0);

        let (transport_b, bound_b) = LanDirectTransport::start(
            aid_b.clone(),
            static_b,
            signer_b.clone() as Arc<dyn Signer>,
            table_b.clone(),
            lookup_b,
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap();

        // A learns about B via the LAN table.
        table_a.upsert(LanPeerRecord {
            agent_id: aid_b.clone(),
            ip: bound_b.ip(),
            port: bound_b.port(),
            last_seen: Instant::now(),
        });

        let (transport_a, _bound_a) = LanDirectTransport::start(
            aid_a.clone(),
            static_a,
            signer_a.clone() as Arc<dyn Signer>,
            table_a.clone(),
            lookup_a,
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(transport_a.reachability(&aid_b), Reachability::IfReachable);

        let mut rx_b = transport_b.take_inbound().expect("inbound rx");

        let outbound = sealed_outbound_dm(&aid_a, b"hello via LAN".to_vec(), 1_700_000_000_000);
        let receipt = transport_a
            .send(&aid_b, outbound.clone(), None)
            .await
            .unwrap();
        assert_eq!(receipt.transport_name, "lan-direct");

        let inbound = tokio::time::timeout(std::time::Duration::from_secs(5), rx_b.recv())
            .await
            .expect("inbound timed out")
            .expect("inbound rx closed");
        assert_eq!(inbound.from, aid_a);
        assert_eq!(inbound.payload, outbound.payload);
        assert_eq!(inbound.transport_name, "lan-direct");
        assert!(inbound.transit.is_some());
    }

    #[tokio::test]
    async fn send_fails_when_no_listener() {
        let aid_a = aid(0x33);
        let aid_b = aid(0x44);

        let signer_a = Arc::new(MlDsaSigner::generate().unwrap()) as Arc<dyn Signer>;
        let static_a = fresh_static(&aid_a.0);
        let table_a = Arc::new(LanPeerTable::new());
        // Bogus port — nothing listens.
        table_a.upsert(LanPeerRecord {
            agent_id: aid_b.clone(),
            ip: "127.0.0.1".parse().unwrap(),
            port: 1, // privileged + unbound; connect will refuse
            last_seen: Instant::now(),
        });
        let lookup_a: ContactPubkeyLookup =
            Arc::new(|_q: &AgentId| -> Option<Vec<u8>> { Some(vec![0xaa; 64]) });

        let (transport_a, _) = LanDirectTransport::start(
            aid_a.clone(),
            static_a,
            signer_a,
            table_a,
            lookup_a,
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap();

        let outbound = sealed_outbound_dm(&aid_a, b"hi".to_vec(), 0);
        let err = transport_a.send(&aid_b, outbound, None).await.unwrap_err();
        assert!(matches!(err, ChatError::MessageTransport(_)), "got {err:?}");
    }

    #[test]
    fn materialise_transit_rejects_mismatched_sender_agent_id() {
        // Outbound -002: a prebuilt TransitEnvelope whose sender doesn't
        // match the local device must be refused rather than forwarded.
        let local = aid(0xa1);
        let foreign = aid(0xb2);
        let foreign_bytes = agent_id_bytes(&foreign).unwrap();
        let bad = TransitEnvelope {
            version: WIRE_VERSION,
            kind: RelayKind::Dm,
            group_id: None,
            tenant_id: None,
            sender_agent_id: RelayAgentId::from_bytes(foreign_bytes),
            sender_machine_id: MachineId::from_bytes([0u8; 32]),
            timestamp_ms: 0,
            epoch: 0,
            ciphertext: vec![1, 2, 3],
            nonce: Vec::new(),
            kem_ciphertext: Vec::new(),
            sender_signature: Vec::new(),
        };
        let envelope = OutboundEnvelope {
            kind: OutboundKind::Dm,
            from_machine_id: None,
            payload: vec![1, 2, 3],
            timestamp_ms: 0,
            transit: Some(bad),
        };
        let err = materialise_transit(&local, &envelope).unwrap_err();
        match err {
            ChatError::Invalid(msg) => assert!(msg.contains("mismatch"), "msg: {msg}"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    /// `materialise_transit` MUST reject any envelope that doesn't
    /// carry a prebuilt sealed `TransitEnvelope`. The v1 fabricated
    /// fallback was removed for parity with `RelayTransport::send` —
    /// there is no LAN-direct escape hatch left, and this is the
    /// contract callers of `LanDirectTransport::send` see.
    #[test]
    fn materialise_transit_without_prebuilt_returns_sealed_required() {
        let local = aid(0xd4);
        let envelope = OutboundEnvelope {
            kind: OutboundKind::Dm,
            from_machine_id: None,
            payload: b"unsealed".to_vec(),
            timestamp_ms: 1_700_000_000_000,
            transit: None,
        };
        let err = materialise_transit(&local, &envelope).unwrap_err();
        assert!(
            matches!(
                err,
                ChatError::SealedRequired { caller } if caller == "LanDirectTransport::send",
            ),
            "expected SealedRequired{{caller=LanDirectTransport::send}}, got {err:?}",
        );
    }

    #[test]
    fn materialise_transit_accepts_matching_prebuilt() {
        let local = aid(0xc3);
        let local_bytes = agent_id_bytes(&local).unwrap();
        let good = TransitEnvelope {
            version: WIRE_VERSION,
            kind: RelayKind::Dm,
            group_id: None,
            tenant_id: None,
            sender_agent_id: RelayAgentId::from_bytes(local_bytes),
            sender_machine_id: MachineId::from_bytes([0u8; 32]),
            timestamp_ms: 0,
            epoch: 0,
            ciphertext: vec![9],
            nonce: Vec::new(),
            kem_ciphertext: Vec::new(),
            sender_signature: Vec::new(),
        };
        let envelope = OutboundEnvelope {
            kind: OutboundKind::Dm,
            from_machine_id: None,
            payload: vec![9],
            timestamp_ms: 0,
            transit: Some(good.clone()),
        };
        let out = materialise_transit(&local, &envelope).unwrap();
        assert_eq!(
            out.sender_agent_id.as_bytes(),
            good.sender_agent_id.as_bytes()
        );
    }

    #[tokio::test]
    async fn send_tcp_connect_timeout() {
        // Outbound -003: an unrouted peer must not stall the caller.
        // 192.0.2.1 is TEST-NET-1 (RFC 5737), guaranteed unrouted on
        // the public internet; SYN goes into the void.
        let aid_a = aid(0x55);
        let aid_b = aid(0x66);

        let signer_a = Arc::new(MlDsaSigner::generate().unwrap()) as Arc<dyn Signer>;
        let static_a = fresh_static(&aid_a.0);
        let table_a = Arc::new(LanPeerTable::new());
        table_a.upsert(LanPeerRecord {
            agent_id: aid_b.clone(),
            ip: "192.0.2.1".parse().unwrap(),
            port: 1,
            last_seen: Instant::now(),
        });
        let lookup_a: ContactPubkeyLookup =
            Arc::new(|_q: &AgentId| -> Option<Vec<u8>> { Some(vec![0xaa; 64]) });

        let (transport_a, _) = LanDirectTransport::start(
            aid_a.clone(),
            static_a,
            signer_a,
            table_a,
            lookup_a,
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap();

        let outbound = sealed_outbound_dm(&aid_a, b"hi".to_vec(), 0);
        let started = tokio::time::Instant::now();
        let err = transport_a.send(&aid_b, outbound, None).await.unwrap_err();
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(12),
            "send took {elapsed:?} — timeout not enforced"
        );
        match err {
            ChatError::MessageTransport(msg) => {
                assert!(msg.contains("timeout"), "msg: {msg}");
            }
            other => panic!("expected MessageTransport, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn handle_inbound_conn_rejects_spoofed_sender_agent_id() {
        // Inbound -001: A connects to B with a proven handshake but
        // embeds sender_agent_id = C in the TransitEnvelope body. B
        // must refuse to forward the spoofed envelope.
        use crate::lan_noise::run_initiator_bound;

        let aid_a = aid(0x77);
        let aid_b = aid(0x88);
        let aid_c = aid(0x99); // a third identity — the spoof target

        let signer_a = Arc::new(MlDsaSigner::generate().unwrap());
        let signer_b = Arc::new(MlDsaSigner::generate().unwrap());
        let pk_a = signer_a.public_key();
        let pk_b = signer_b.public_key();

        let lookup_a: ContactPubkeyLookup = {
            let aid_b = aid_b.clone();
            let pk_b = pk_b.clone();
            Arc::new(move |q: &AgentId| {
                if *q == aid_b {
                    Some(pk_b.clone())
                } else {
                    None
                }
            })
        };
        let lookup_b: ContactPubkeyLookup = {
            let aid_a = aid_a.clone();
            let pk_a = pk_a.clone();
            Arc::new(move |q: &AgentId| {
                if *q == aid_a {
                    Some(pk_a.clone())
                } else {
                    None
                }
            })
        };

        let static_a = fresh_static(&aid_a.0);
        let static_b = fresh_static(&aid_b.0);

        let (transport_b, bound_b) = LanDirectTransport::start(
            aid_b.clone(),
            static_b,
            signer_b.clone() as Arc<dyn Signer>,
            Arc::new(LanPeerTable::new()),
            lookup_b,
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap();

        let mut rx_b = transport_b.take_inbound().expect("inbound rx");

        // Manually run the initiator side so we can inject a forged
        // TransitEnvelope after the handshake.
        let local_aid_bytes = agent_id_bytes(&aid_a).unwrap();
        let peer_aid_bytes = agent_id_bytes(&aid_b).unwrap();
        let mut stream = TcpStream::connect(bound_b).await.unwrap();
        stream.write_all(&local_aid_bytes).await.unwrap();
        let prologue = make_prologue(&local_aid_bytes, &peer_aid_bytes);
        let static_pub = *static_a.x25519_public();
        let static_sec = *static_a.x25519_secret();
        let created_at = static_a.created_at_ms();
        let lookup_for_handshake = lookup_a.clone();
        let signer_for_handshake = signer_a.clone() as Arc<dyn Signer>;
        let (mut ts, _verified) = run_initiator_bound(
            &mut stream,
            &prologue,
            &static_sec,
            &local_aid_bytes,
            &static_pub,
            created_at,
            sign_blob(signer_for_handshake),
            &move |q: &[u8; 32]| {
                let aid = AgentId::parse(hex::encode(q)).ok()?;
                lookup_for_handshake(&aid)
            },
        )
        .await
        .unwrap();

        // Forge a TransitEnvelope claiming aid_c is the sender (not A).
        let forged = TransitEnvelope {
            version: WIRE_VERSION,
            kind: RelayKind::Dm,
            group_id: None,
            tenant_id: None,
            sender_agent_id: RelayAgentId::from_bytes(agent_id_bytes(&aid_c).unwrap()),
            sender_machine_id: MachineId::from_bytes([0u8; 32]),
            timestamp_ms: 0,
            epoch: 0,
            ciphertext: b"spoofed".to_vec(),
            nonce: Vec::new(),
            kem_ciphertext: Vec::new(),
            sender_signature: Vec::new(),
        };
        let bytes = postcard::to_allocvec(&forged).unwrap();
        write_app_frame(&mut stream, &mut ts, &bytes).await.unwrap();
        let _ = stream.shutdown().await;

        // The spoofed envelope must NOT be forwarded. Wait briefly and
        // assert nothing arrives.
        let res = tokio::time::timeout(Duration::from_millis(500), rx_b.recv()).await;
        assert!(
            res.is_err(),
            "spoofed envelope was forwarded as {:?}",
            res.unwrap()
        );
    }

    #[tokio::test]
    async fn inbound_handshake_times_out_and_releases_slot() {
        // Inbound -004: a raw TCP connection that never writes the
        // 32-byte init header must be torn down within the handshake
        // budget, freeing the semaphore slot for a subsequent legit
        // handshake.
        let aid_b = aid(0xee);
        let signer_b = Arc::new(MlDsaSigner::generate().unwrap()) as Arc<dyn Signer>;
        let static_b = fresh_static(&aid_b.0);
        let lookup_b: ContactPubkeyLookup =
            Arc::new(|_q: &AgentId| -> Option<Vec<u8>> { Some(vec![0xaa; 64]) });

        let (transport_b, bound_b) = LanDirectTransport::start(
            aid_b.clone(),
            static_b,
            signer_b,
            Arc::new(LanPeerTable::new()),
            lookup_b,
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap();
        let _ = transport_b; // keep the listener alive

        // Open a TCP connection that goes silent forever — never
        // writes the 32-byte init aid header. The listener task should
        // give up after LAN_HANDSHAKE_TIMEOUT (10s) and drop the conn.
        let started = tokio::time::Instant::now();
        let stalled = TcpStream::connect(bound_b).await.unwrap();

        // Wait for the responder to drop us. The server never writes,
        // so reading either yields EOF (Ok(0)) when the listener task
        // closes the socket, or an Err on RST — both signal teardown.
        let read_result = tokio::time::timeout(Duration::from_secs(12), async {
            let mut buf = [0u8; 1];
            let mut s = stalled;
            let _ = s.read(&mut buf).await;
        })
        .await;
        let elapsed = started.elapsed();
        assert!(
            read_result.is_ok(),
            "stalled inbound was not closed within 12s (elapsed {elapsed:?})"
        );
        assert!(
            elapsed >= Duration::from_secs(9),
            "stalled inbound closed too early ({elapsed:?}) — timeout may be wrong"
        );
    }
}
