# LAN-direct transport — design

**Date:** 2026-05-29
**Scope:** Add a same-LAN transport for chat envelopes that runs
alongside `RelayTransport`. mDNS-based discovery; Noise XX channel
with an ML-DSA-65 channel-binding signature; encrypted-at-rest
X25519 static keypair; opt-in toggle in Settings → Network.
**Roadmap task:** #100. Future seam: share-card v3 (#144) lets us
upgrade XX → IK without a chat-layer change.

## 1. Goals and non-goals

### 1.1 Goals
- Make a DM to a peer on the same Wi-Fi/Ethernet take the LAN path
  instead of the relay, transparently.
- Bind the LAN session to the same `agent_id` the relay path uses,
  with no new trust ladder — leverage the ML-DSA-65 pubkey already
  on the local contact record from share-URI import.
- Survive a relay outage for any LAN-co-resident peer pair.
- No new state visible to the chat layer: `Router::send` still picks
  by `Reachability`, `handle_inbound` still dispatches on
  `env.transit`.
- Stay pure-Rust, no host-daemon dependency (no Avahi/Bonjour).

### 1.2 Non-goals
- NAT traversal / WAN reach. LAN-only by design.
- Auto-add discovered peers to contacts. TOFU stays at share-URI.
- Per-session resumption / 0-RTT. Always fresh XX.
- PQ-hybrid Noise patterns. Defer to v2; chat payload underneath is
  already ML-KEM-768 sealed, so the LAN session protects only
  envelope metadata (sender, recipient, timing).
- Mobile (Android `MulticastLock`, iOS `NSNetService`). Desktop-first;
  mobile parity tracked in ios-catchup.

## 2. Identity binding

### 2.1 Keys

| Key | Lives | Used for |
| --- | --- | --- |
| ML-DSA-65 (signing) | x0xd, accessed via `Signer::sign` | Channel-binding signature on Noise msg2/msg3 |
| ML-KEM-768 (KEM) | `<data_dir>/identity.json.enc` | Chat content envelope sealing (unchanged) |
| **X25519 static (new)** | `<data_dir>/lan_static.json.enc` | Long-lived Noise XX static identity |

The X25519 static keypair is generated on first launch via
`x25519-dalek::StaticSecret`, sealed with the same `MasterKey`
already resolved for `identity.json.enc`. Regenerated on
`agent_id_hex` mismatch — mirrors `FetchitIdentity::load_or_create`.

### 2.2 The signed binding

A LAN handshake commits to:

```
SIGN_DOMAIN_LAN_NOISE
|| version(1)
|| agent_id_self(32)
|| x25519_static_pub_self(32)
|| handshake_hash_at_signing_time
```

Each side signs its half via `Signer::sign` (so X0xdSigner mediates;
the ML-DSA-65 secret never leaves x0xd). Verification reuses
`chat_crypto::ml_dsa_verify` against the ML-DSA pubkey stored on the
local contact record from share-URI import.

`SIGN_DOMAIN_LAN_NOISE` is a new constant added to `chat_crypto.rs`
alongside the existing `SIGN_DOMAIN_ENVELOPE` / `SIGN_DOMAIN_CARD`.

## 3. Noise XX channel

### 3.1 Pattern
`Noise_XX_25519_ChaChaPoly_BLAKE2s` (snow's default XX suite).

Why XX, not IK: IK requires the initiator to know the responder's
X25519 static up front. Share-card v2 carries only ML-DSA + ML-KEM
pubkeys, so v1 cannot bootstrap IK. XX lets both peers learn each
other's static during the handshake; the ML-DSA signatures on msg2
and msg3 are what authenticate those statics back to the AgentId.

When share-card v3 lands and can publish the X25519 static, the
transport switches to IK behind a `suite=` TXT bump — one
handshake-pattern swap, no chat-layer change.

### 3.2 Prologue
```
b"fetchit-lan-v1"
|| initiator_advertised_agent_id(32)
|| responder_advertised_agent_id(32)
```
Folds both mDNS-advertised AgentIds into the handshake hash. A
relay or MITM that swaps announcements between two real peers
breaks the prologue commitment and the post-handshake signature
fails to verify.

### 3.3 Message payloads
- msg1 (`-> e`): empty payload.
- msg2 (`<- e, ee, s, es`): payload =
  `{agent_id: [u8;32], created_at_ms: u64, sig: Vec<u8>}` signed
  per §2.2.
- msg3 (`-> s, se`): payload = initiator's matching signed blob.

### 3.4 Framing
Post-handshake, both `snow::TransportState`s exchange frames as
`u32be length || ciphertext`. Max frame body 65 535 bytes; framed
payload is a serialized `TransitEnvelope` (the same shape the
relay path carries). `dispatch_inbound` is unchanged.

### 3.5 Rekey / reconnect
- One handshake per TCP session. No session tickets, no PSK cache.
- TCP keepalive on; 30 s read-idle timeout drops the
  `TransportState`s and marks the `LanPeerTable` entry stale.
- Reconnect is lazy: triggered by the next outbound send that hits
  the Router. Fresh XX every time. Forward secrecy per session via
  XX's ephemerals.

## 4. Discovery (mDNS)

### 4.1 Service
- Service name: `_fetchit-chat._tcp.local.`
- Instance: `fetchit-<aid_first12hex>.<service>`
- SRV: ephemeral TCP port bound on `0.0.0.0:0` at start.
- Crate: `mdns-sd` (pure-Rust, no system daemon).

### 4.2 TXT record
```
v=1
aid=<64-hex-agent-id>
port=<u16>          // duplicate of SRV; saves a query
```
Deliberately minimal — no display name, no signing pubkey, no
binding signature. Everything trust-relevant is verified inside
Noise against the trusted contact card. Strangers on the LAN can't
spoof a name they don't own.

### 4.3 LanPeerTable
In-memory `HashMap<AgentId, LanPeerRecord>` populated by a long-
running browser task. Stale TTL 5 minutes since last announce. The
table is used in two places: `LanDirectTransport::reachability` and
the Nearby sidebar surface (§5).

## 5. UI surface

### 5.1 Settings → Network
New checkbox **Enable LAN delivery (experimental)**, default off.
Help text: *"Send chat directly between devices on the same network.
Falls back to relay automatically."* Persisted to the existing
`apps/fetchit-desktop/src-tauri/src/settings.rs`.

When the toggle is OFF, no announce, no browse, no Nearby section.

### 5.2 Nearby section in the sidebar
When the toggle is ON, the sidebar gains a **Nearby** section below
the conversation list. Each row shows an AgentId short prefix
(no display name — TXT doesn't carry one) and an **Add** button.
Click → opens the existing Add-contact dialog with the AgentId
hinted; the user still pastes the share URI to actually trust the
peer. TOFU is preserved.

A LAN-announced AgentId that already maps to a contact is filtered
out of Nearby — it just makes that contact's deliveries faster.

## 6. Transport plumbing

### 6.1 LanDirectTransport
New module `crates/fetchit-chat/src/lan_direct_transport.rs`
implementing the existing `Transport` trait:

- `name() -> "lan-direct"`
- `reachability(&AgentId)` returns `IfReachable` iff (a) the
  `LanPeerTable` has a fresh entry **and** (b) the contact-pubkey
  lookup returns `Some(ml_dsa_pub)`. Else `No`.
- `send` dials TCP, runs `lan_noise::run_initiator`, frames the
  prebuilt `TransitEnvelope`, returns a `SendReceipt` with
  `transport_name: "lan-direct"`.
- `take_inbound` returns the one-shot mpsc receiver fed by the
  inbound accept-loop.

### 6.2 ClientBuilder wiring
New `ClientBuilder::enable_lan_direct(bool)` opt-in. In
`build_with_chat`, when enabled: load `LanStaticIdentity`, bind a
listener on `0.0.0.0:0`, spawn the mDNS announce + browser, and
push `LanDirectTransport` onto the Router **before** the relay
transport so LAN-`IfReachable` wins by registration order; falls
through to relay on send error per the existing Router contract.

### 6.3 Desktop pump
`apps/fetchit-desktop/src-tauri/src/chat.rs` gains
`spawn_lan_inbound` — a copy of `spawn_relay_inbound` calling
`take_transport_inbound("lan-direct")`. `handle_inbound` is
transport-agnostic and reused verbatim. A new `chat:nearby` Tauri
event mirrors the `LanPeerTable` to the frontend store.

## 7. Crates added
All to `crates/fetchit-chat/Cargo.toml`, all pure-Rust:

- `snow = "0.10"` — Noise XX.
- `mdns-sd = "0.13"` — pure-Rust DNS-SD.
- `x25519-dalek = { version = "2", features = ["static_secrets"] }`.

No workspace-level changes; no `unsafe`; no host daemon.

## 8. Security model

Threats and mitigations:

- **Spoofed AgentId in mDNS TXT.** Prologue commits both
  advertised AgentIds; post-handshake signature ties the X25519
  static to the AgentId via the trusted contact's ML-DSA pubkey.
- **MITM between two real peers.** Same defence — handshake hash
  diverges.
- **Stranger on the LAN dials us.** Their AgentId isn't in our
  contact store → contact-pubkey lookup returns `None` →
  `reachability::No` → no dial outbound, and inbound dials hit a
  verifier that has no key to check against and abort.
- **Replay across reconnects.** Fresh XX per session; chat-layer
  envelope already carries its own nonce + epoch so transport
  replay is moot.
- **Inbound flood.** Hard-coded conservative caps: ≤ 4 concurrent
  handshakes per remote IP, ≤ 32 per process.
- **Vault file leak.** `lan_static.json.enc` reuses `seal_to_path`
  with mode 0o600, ChaCha20-Poly1305 + Argon2id-from-passphrase /
  OS keychain master key. X25519 secret bytes use `Zeroizing`.

PQ caveat: XX is classical X25519. A future passive attacker with
a CRQC recovers the LAN session keys for any captured stream.
Chat payload is ML-KEM-768 sealed, so plaintext stays
PQ-confidential; LAN session compromise leaks routing metadata
only. PQ-hybrid Noise is tracked separately.

A one-paragraph `docs/SECURITY.md` entry lists the new
load-bearing files (`lan_direct_transport.rs`, `lan_noise.rs`,
`lan_static.rs`) alongside the existing iframe/CSP boundary.

## 9. Testing

- Unit tests in each new module (vault round-trip, sign+verify
  round-trip, Noise XX handshake fixture, mDNS announce/browse on
  loopback marked `#[ignore]`, reachability gating).
- `crates/fetchit-chat/tests/live_lan.rs` — `#[ignore]`'d
  two-peer integration test on loopback: two `Client`s with
  distinct data-dirs and signers, cross-import each other's
  contact card, `enable_lan_direct(true)`, no relay. Asserts the
  receipt carries `transport_name == "lan-direct"`.
- Manual two-laptop bring-up: documented step list in the PR body
  and in `private/test-checklist.md`.
