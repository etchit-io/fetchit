# LAN-direct transport — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a same-LAN transport for chat envelopes — mDNS
discovery + Noise XX with ML-DSA-65 channel binding — that runs
alongside `RelayTransport` and beats it on `Reachability`.

**Architecture:** New `LanDirectTransport` impl of the existing
`Transport` trait, sibling sealed vault for an X25519 static
keypair, signed binding against the contact's ML-DSA pubkey. Opt-in
toggle, default off; minimal Nearby section in the desktop sidebar.

**Tech Stack:** Rust workspace (`crates/fetchit-chat`), Tauri 2 +
TS desktop shell, `snow` (Noise), `mdns-sd` (DNS-SD),
`x25519-dalek` (static X25519). Spec:
`docs/superpowers/specs/2026-05-29-lan-direct-transport-design.md`.

---

## File map

| File | Action |
| --- | --- |
| `crates/fetchit-chat/Cargo.toml` | Add `snow`, `mdns-sd`, `x25519-dalek` |
| `crates/fetchit-chat/src/lib.rs` | Re-export new modules |
| `crates/fetchit-chat/src/lan_static.rs` | New: sealed X25519 vault |
| `crates/fetchit-chat/src/chat_crypto.rs` | Add `SIGN_DOMAIN_LAN_NOISE` + `lan_binding_bytes` |
| `crates/fetchit-chat/src/lan_noise.rs` | New: framed Noise XX + binding |
| `crates/fetchit-chat/src/lan_discovery.rs` | New: mDNS announce + browse + peer table |
| `crates/fetchit-chat/src/lan_direct_transport.rs` | New: `Transport` impl |
| `crates/fetchit-chat/src/client.rs` | `ClientBuilder::enable_lan_direct` + Router wiring |
| `crates/fetchit-chat/tests/live_lan.rs` | New: `#[ignore]` two-peer live test |
| `apps/fetchit-desktop/src-tauri/src/chat.rs` | `spawn_lan_inbound`; `chat_list_nearby` + `chat:nearby` event |
| `apps/fetchit-desktop/src-tauri/src/settings.rs` | `lan_direct_enabled` field |
| `apps/fetchit-desktop/src-tauri/src/lib.rs` | Register new commands |
| `apps/fetchit-desktop/src/settings.ts` | Toggle UI + get/set wiring |
| `apps/fetchit-desktop/src/chat/state.ts` | `nearbyPeers` state slice |
| `apps/fetchit-desktop/src/chat/sidebar.ts` | Nearby section render |
| `apps/fetchit-desktop/src/chat/panel.ts` | Subscribe `chat:nearby`, dispatch Add |
| `docs/SECURITY.md` | New LAN paragraph |

---

### Task 1: `LanStaticIdentity` vault round-trip

**Files:**
- Create: `crates/fetchit-chat/src/lan_static.rs`
- Modify: `crates/fetchit-chat/src/lib.rs`
- Modify: `crates/fetchit-chat/Cargo.toml`

- [ ] **Step 1: Failing tests**

In `lan_static.rs` `mod tests`, write:
- `first_launch_creates_x25519_keypair`
- `second_load_returns_same_keypair`
- `agent_id_rotation_regenerates_keypair`

Mirror `chat_identity.rs::tests` patterns: seal to a `TempDir`,
load again, assert pub-byte equality across reloads and inequality
across agent_id rotation.

- [ ] **Step 2: Run — confirm fail**

`cargo test -p fetchit-chat lan_static -- --nocapture`
Expected: compile errors (module missing).

- [ ] **Step 3: Implement**

```rust
//! Sealed vault for the LAN-direct Noise X25519 static keypair.
use crate::at_rest::{open_from_path, seal_to_path, KdfId, MasterKey};
use crate::error::ChatError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const LAN_STATIC_FILE: &str = "lan_static.json.enc";

#[derive(Debug, Serialize, Deserialize)]
struct LanStaticVaultPayload {
    version: u8,
    agent_id_hex: String,
    x25519_pub_b64: String,
    x25519_sec_b64: Zeroizing<String>,
    created_at_ms: u64,
}

pub struct LanStaticIdentity {
    agent_id_hex: String,
    x25519_pub: [u8; 32],
    x25519_sec: Zeroizing<[u8; 32]>,
}

impl LanStaticIdentity {
    pub fn load_or_create(
        data_dir: &Path,
        master: &MasterKey,
        agent_id_hex: &str,
        kdf: KdfId,
        argon_salt: Option<&[u8]>,
    ) -> Result<Self, ChatError> { /* ... mirror chat_identity ... */ }

    pub fn x25519_public(&self) -> [u8; 32] { self.x25519_pub }
    pub fn x25519_secret(&self) -> &[u8; 32] { &self.x25519_sec }
    pub fn agent_id_hex(&self) -> &str { &self.agent_id_hex }
}
```

Add to `Cargo.toml`:
```toml
x25519-dalek = { version = "2", features = ["static_secrets", "zeroize"] }
```

Add `pub mod lan_static;` to `lib.rs`.

- [ ] **Step 4: Run — confirm pass**

`cargo test -p fetchit-chat lan_static`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -s -m "feat(chat): sealed X25519 static-keypair vault for LAN transport"
```

---

### Task 2: `SIGN_DOMAIN_LAN_NOISE` + binding helpers

**Files:**
- Modify: `crates/fetchit-chat/src/chat_crypto.rs`

- [ ] **Step 1: Failing tests**

In `chat_crypto.rs` `mod tests`, add:
- `lan_binding_bytes_layout` — assert produced bytes are
  `domain || version_byte || agent_id(32) || x25519_pub(32) || ts_be(8)`.
- `lan_binding_sign_and_verify_roundtrip` — generate an `MlDsaSigner`
  fixture, sign `lan_binding_bytes(...)`, `ml_dsa_verify` succeeds.
- `lan_binding_tamper_fails` — flip a byte → verify fails.

- [ ] **Step 2: Run — confirm fail**

`cargo test -p fetchit-chat chat_crypto::tests::lan_binding`
Expected: compile errors.

- [ ] **Step 3: Implement**

```rust
pub const SIGN_DOMAIN_LAN_NOISE: &[u8] = b"fetchit/lan-noise/v1";

#[must_use]
pub fn lan_binding_bytes(
    agent_id: &[u8; 32],
    x25519_pub: &[u8; 32],
    created_at_ms: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        SIGN_DOMAIN_LAN_NOISE.len() + 1 + 32 + 32 + 8,
    );
    out.extend_from_slice(SIGN_DOMAIN_LAN_NOISE);
    out.push(1);
    out.extend_from_slice(agent_id);
    out.extend_from_slice(x25519_pub);
    out.extend_from_slice(&created_at_ms.to_be_bytes());
    out
}
```

- [ ] **Step 4: Run — confirm pass**

`cargo test -p fetchit-chat chat_crypto`
Expected: existing tests still pass; 3 new passes.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -s -m "feat(chat): SIGN_DOMAIN_LAN_NOISE + binding bytes helper"
```

---

### Task 3: Noise XX handshake fixture

**Files:**
- Create: `crates/fetchit-chat/src/lan_noise.rs`
- Modify: `crates/fetchit-chat/src/lib.rs`
- Modify: `crates/fetchit-chat/Cargo.toml`

- [ ] **Step 1: Failing tests**

In `lan_noise.rs` `mod tests`:
- `xx_handshake_completes_and_cipherstates_match` — drive both
  sides over `tokio::io::duplex`, complete the XX, write one frame
  each way, assert decryption succeeds.
- `prologue_mismatch_aborts_handshake` — initiator and responder
  supply different prologue bytes → handshake error.

- [ ] **Step 2: Run — confirm fail**

`cargo test -p fetchit-chat lan_noise`
Expected: compile errors.

- [ ] **Step 3: Implement**

Add `snow = "0.10"` to `Cargo.toml`. Create `lan_noise.rs`:

```rust
//! Framed Noise XX over an async byte stream. No ML-DSA layer
//! here — see `run_initiator_bound` / `run_responder_bound` in
//! task 4 for the channel-binding variant.
use crate::error::ChatError;
use snow::{HandshakeState, TransportState};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_FRAME: usize = 65_535;
const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

pub struct NoiseChannel {
    pub send: TransportState,
    pub recv: TransportState,
}

pub async fn run_initiator_plain<S>(
    stream: &mut S,
    prologue: &[u8],
    static_sec: &[u8; 32],
) -> Result<TransportState, ChatError>
where S: AsyncRead + AsyncWrite + Unpin { /* ... */ }

pub async fn run_responder_plain<S>(
    stream: &mut S,
    prologue: &[u8],
    static_sec: &[u8; 32],
) -> Result<TransportState, ChatError>
where S: AsyncRead + AsyncWrite + Unpin { /* ... */ }

pub async fn write_frame<W>(w: &mut W, ts: &mut TransportState, plaintext: &[u8])
    -> Result<(), ChatError>
where W: AsyncWrite + Unpin { /* len-prefixed, MAX_FRAME guard */ }

pub async fn read_frame<R>(r: &mut R, ts: &mut TransportState)
    -> Result<Vec<u8>, ChatError>
where R: AsyncRead + Unpin { /* mirror, with MAX_FRAME cap */ }
```

Add `pub mod lan_noise;` to `lib.rs`.

- [ ] **Step 4: Run — confirm pass**

`cargo test -p fetchit-chat lan_noise`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -s -m "feat(chat): Noise XX duplex fixture for LAN transport"
```

---

### Task 4: Noise XX + ML-DSA channel-binding

**Files:**
- Modify: `crates/fetchit-chat/src/lan_noise.rs`

- [ ] **Step 1: Failing tests**

Add to `lan_noise::tests`:
- `xx_with_binding_succeeds_when_signatures_verify`
- `xx_aborts_when_responder_signature_is_forged`
- `xx_aborts_when_handshake_hash_changed`
- `xx_aborts_when_advertised_agent_id_differs_from_signed`

Each uses fixture `MlDsaSigner`s and a `peer_pubkey_lookup`
closure that returns the expected ML-DSA pubkey for the
advertised AgentId.

- [ ] **Step 2: Run — confirm fail**

`cargo test -p fetchit-chat lan_noise::tests::xx_with_binding`
Expected: compile error or test failure.

- [ ] **Step 3: Implement**

Add to `lan_noise.rs`:

```rust
pub struct LanBindingProof {
    pub agent_id: [u8; 32],
    pub x25519_pub: [u8; 32],
    pub created_at_ms: u64,
    pub sig: Vec<u8>,
}

pub async fn run_initiator_bound<S, F, Fut>(
    stream: &mut S,
    prologue: &[u8],
    my_static_sec: &[u8; 32],
    my_static_pub: &[u8; 32],
    my_agent_id: &[u8; 32],
    sign_blob: F,
    peer_pubkey_lookup: impl Fn(&[u8; 32]) -> Option<Vec<u8>>,
) -> Result<(TransportState, [u8; 32]), ChatError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>, ChatError>>,
{
    // 1. Run XX through msg1, msg2 (receive responder's binding).
    // 2. Verify msg2 payload:
    //    bytes = lan_binding_bytes(peer_agent_id, peer_static_pub, ts)
    //         || handshake_hash_snapshot
    //    ml_dsa_verify(peer_pubkey_lookup(peer_agent_id)?, &bytes, &sig)
    // 3. Build our binding bytes, call sign_blob(bytes) → sig.
    // 4. Send msg3 with our LanBindingProof as payload.
    // 5. Return verified peer agent_id.
}

pub async fn run_responder_bound<S, F, Fut>(/* mirror */) { /* ... */ }
```

Signing is delegated through `sign_blob` so callers can plug
`X0xdSigner` or the `MlDsaSigner` test fixture without `lan_noise`
depending on either.

- [ ] **Step 4: Run — confirm pass**

`cargo test -p fetchit-chat lan_noise`
Expected: 6 passed (2 plain + 4 bound).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -s -m "feat(chat): ML-DSA channel-binding over Noise XX (msg2/msg3 payloads)"
```

---

### Task 5: mDNS announce + browse

**Files:**
- Create: `crates/fetchit-chat/src/lan_discovery.rs`
- Modify: `crates/fetchit-chat/src/lib.rs`
- Modify: `crates/fetchit-chat/Cargo.toml`

- [ ] **Step 1: Failing test**

In `lan_discovery.rs` `mod tests`:
- `#[ignore]` `announce_and_browse_returns_self_record` — single
  process: announce with `aid=<hex>` + random port; browser sees
  the record within 5 s and parses TXT.

(Marked `#[ignore]` because multicast flakes in CI; run locally.)

- [ ] **Step 2: Run — confirm fail**

`cargo test -p fetchit-chat lan_discovery -- --ignored --nocapture`
Expected: compile errors.

- [ ] **Step 3: Implement**

Add `mdns-sd = "0.13"` to `Cargo.toml`. Create `lan_discovery.rs`:

```rust
//! mDNS service discovery for LanDirectTransport.
use crate::identity::AgentId;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

pub const SERVICE_TYPE: &str = "_fetchit-chat._tcp.local.";
pub const PEER_TTL: std::time::Duration =
    std::time::Duration::from_secs(300);

#[derive(Clone, Debug)]
pub struct LanPeerRecord {
    pub ip: IpAddr,
    pub port: u16,
    pub last_seen: Instant,
}

pub struct LanPeerTable {
    entries: Mutex<HashMap<AgentId, LanPeerRecord>>,
}

impl LanPeerTable {
    pub fn new() -> Self { /* ... */ }
    pub fn insert(&self, aid: AgentId, rec: LanPeerRecord) { /* ... */ }
    pub fn lookup(&self, aid: &AgentId) -> Option<LanPeerRecord> { /* drops stale */ }
    pub fn snapshot(&self) -> Vec<(AgentId, LanPeerRecord)> { /* drops stale */ }
}

pub async fn spawn_browser(table: Arc<LanPeerTable>) -> JoinHandle<()> { /* ... */ }
pub fn announce(aid_hex: &str, port: u16) -> mdns_sd::ServiceInfo { /* ... */ }
```

Add `pub mod lan_discovery;` to `lib.rs`.

- [ ] **Step 4: Run — confirm pass**

`cargo test -p fetchit-chat lan_discovery -- --ignored`
Expected: 1 passed locally; ignored in CI.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -s -m "feat(chat): mDNS service discovery + LanPeerTable"
```

---

### Task 6: `LanDirectTransport` skeleton + reachability gate

**Files:**
- Create: `crates/fetchit-chat/src/lan_direct_transport.rs`
- Modify: `crates/fetchit-chat/src/lib.rs`

- [ ] **Step 1: Failing tests**

In `lan_direct_transport.rs` `mod tests`:
- `name_is_lan_direct`
- `reachability_no_when_peer_not_in_lan_table`
- `reachability_no_when_peer_not_in_contact_store`
- `reachability_if_reachable_when_both_present`

- [ ] **Step 2: Run — confirm fail**

`cargo test -p fetchit-chat lan_direct_transport`
Expected: compile errors.

- [ ] **Step 3: Implement**

```rust
//! LAN-direct transport. mDNS + Noise XX + ML-DSA channel-binding.
use crate::{
    error::ChatError,
    identity::AgentId,
    lan_discovery::{LanPeerRecord, LanPeerTable},
    lan_static::LanStaticIdentity,
    transport::{
        InboundEnvelope, OutboundEnvelope, Reachability, SendReceipt,
        Transport,
    },
};
use async_trait::async_trait;
use fetchit_relay_client::Signer;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::mpsc;

pub type ContactPubkeyLookup = Arc<
    dyn Fn(&AgentId) -> Option<Vec<u8>> + Send + Sync,
>;

pub struct LanDirectTransport {
    local_agent_id: AgentId,
    local_static: Arc<LanStaticIdentity>,
    signer: Arc<dyn Signer>,
    table: Arc<LanPeerTable>,
    contact_pubkey_lookup: ContactPubkeyLookup,
    inbound_rx: StdMutex<Option<mpsc::UnboundedReceiver<InboundEnvelope>>>,
}

#[async_trait]
impl Transport for LanDirectTransport {
    fn name(&self) -> &'static str { "lan-direct" }

    fn reachability(&self, to: &AgentId) -> Reachability {
        if self.table.lookup(to).is_none() { return Reachability::No; }
        if (self.contact_pubkey_lookup)(to).is_none() { return Reachability::No; }
        Reachability::IfReachable
    }

    async fn send(&self, _to: &AgentId, _env: OutboundEnvelope)
        -> Result<SendReceipt, ChatError>
    {
        Err(ChatError::MessageTransport("not yet implemented".into()))
    }

    fn take_inbound(&self) -> Option<mpsc::UnboundedReceiver<InboundEnvelope>> {
        self.inbound_rx.lock().ok().and_then(|mut g| g.take())
    }
}
```

`send` is stubbed; filled in next step.

- [ ] **Step 4: Run — confirm pass**

`cargo test -p fetchit-chat lan_direct_transport`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -s -m "feat(chat): LanDirectTransport skeleton + reachability gate"
```

---

### Task 7: `LanDirectTransport::send` + accept-loop

**Files:**
- Modify: `crates/fetchit-chat/src/lan_direct_transport.rs`

- [ ] **Step 1: Failing tests**

Add:
- `send_completes_and_responder_decodes_transit` — two transport
  instances on 127.0.0.1, cross-registered; send a prebuilt
  `OutboundEnvelope { transit: Some(env), .. }` from A to B; B's
  inbound mpsc yields one `InboundEnvelope` with
  `transport_name == "lan-direct"` and byte-equal `transit`.
- `send_fails_when_no_listener` — peer in table but TCP refused →
  `ChatError::MessageTransport`.

- [ ] **Step 2: Run — confirm fail**

`cargo test -p fetchit-chat lan_direct_transport::tests::send_`
Expected: failure (`send` is the stub from task 6).

- [ ] **Step 3: Implement**

Wire `send` to `lan_noise::run_initiator_bound`, frame the
`TransitEnvelope` bytes (or fabricate v1-shape like
`relay_transport.rs` when `envelope.transit` is `None`), return
`SendReceipt { transport_name: "lan-direct", … }`.

Add `pub async fn start_listener(bind: SocketAddr, …) ->
(SocketAddr, mpsc::UnboundedReceiver<InboundEnvelope>)`: accept
loop spawning per-conn responder tasks. Hard caps: ≤ 4 in-flight
handshakes per remote IP, ≤ 32 process-wide. Each frame becomes
one `InboundEnvelope` on the shared mpsc.

- [ ] **Step 4: Run — confirm pass**

`cargo test -p fetchit-chat lan_direct_transport`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -s -m "feat(chat): LanDirectTransport send/listen — framed Noise XX over TCP"
```

---

### Task 8: `ClientBuilder::enable_lan_direct` + Router wiring

**Files:**
- Modify: `crates/fetchit-chat/src/client.rs`

- [ ] **Step 1: Failing tests**

Add to `client.rs` `mod tests`:
- `lan_direct_disabled_by_default_router_has_only_relay` — build
  with `.relay_url(..)` only; assert `Router::transports().len()
  == 1` and first name == `"relay"`.
- `lan_direct_enabled_router_has_lan_first_then_relay` — same
  build with `.enable_lan_direct(true)`; len == 2, transports[0]
  is `"lan-direct"`, transports[1] is `"relay"`.

- [ ] **Step 2: Run — confirm fail**

`cargo test -p fetchit-chat client::tests::lan_direct`
Expected: compile error (builder method missing).

- [ ] **Step 3: Implement**

```rust
impl ClientBuilder {
    pub fn enable_lan_direct(mut self, enabled: bool) -> Self {
        self.enable_lan_direct = enabled;
        self
    }
}
```

In `build_with_chat`, when `enable_lan_direct`:
1. `LanStaticIdentity::load_or_create(...)`.
2. Bind TCP listener on `0.0.0.0:0`, capture port.
3. `lan_discovery::announce(aid, port)`.
4. `lan_discovery::spawn_browser(table.clone())`.
5. Construct `LanDirectTransport` (pulling contact-pubkey lookup
   from the existing chat store).
6. `router.add(lan_transport)` **before** the relay transport.

Add a way to introspect transports in test builds — either
`Router::transports() -> &[Arc<dyn Transport>]` (already exists)
or expose `Client::transports_for_test()`.

- [ ] **Step 4: Run — confirm pass**

`cargo test -p fetchit-chat client`
Expected: existing tests pass; 2 new pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -s -m "feat(chat): ClientBuilder::enable_lan_direct wires LAN onto the Router"
```

---

### Task 9: Desktop `spawn_lan_inbound` pump + Nearby plumbing

**Files:**
- Modify: `apps/fetchit-desktop/src-tauri/src/chat.rs`
- Modify: `apps/fetchit-desktop/src-tauri/src/settings.rs`
- Modify: `apps/fetchit-desktop/src-tauri/src/lib.rs`

- [ ] **Step 1: Failing tests**

In `apps/fetchit-desktop/src-tauri/src/settings.rs` `mod tests`,
add `lan_direct_enabled_defaults_false_and_round_trips`.

(No Rust unit test for the pump itself — compile-time gate
suffices; functional test is the live two-peer test in task 11.)

- [ ] **Step 2: Run — confirm fail**

`(cd apps/fetchit-desktop/src-tauri && cargo test lan_direct_enabled)`
Expected: compile error.

- [ ] **Step 3: Implement**

Add to `settings.rs`:
```rust
#[serde(default)]
pub lan_direct_enabled: bool,
```

Add Tauri commands in `chat.rs` (or a new `lan_settings.rs`):
- `fn lan_direct_enabled(state) -> bool`
- `fn set_lan_direct_enabled(state, enabled: bool)`
- `async fn chat_list_nearby(state) -> Vec<NearbyPeer>` where
  `NearbyPeer { agent_id_hex, ip, port, last_seen_ms }`.

Mirror `spawn_relay_inbound` as `spawn_lan_inbound`:

```rust
async fn spawn_lan_inbound(app: AppHandle, client: Arc<Client>) {
    let Some(mut rx) = client.take_transport_inbound("lan-direct") else {
        return;
    };
    while let Some(env) = rx.recv().await {
        handle_inbound(&app, &client, env).await;
    }
}
```

Call from `spawn_event_pump`. In `ChatState::get`, pass
`settings.lan_direct_enabled` into `ClientBuilder::enable_lan_direct`.

Emit `chat:nearby` on a 5 s interval (or whenever the
`LanPeerTable` mutates) with the snapshot filtered against the
local contact store.

Register the new commands in `lib.rs` `invoke_handler!`.

- [ ] **Step 4: Run — confirm pass**

```bash
(cd apps/fetchit-desktop/src-tauri && cargo test)
(cd apps/fetchit-desktop/src-tauri && cargo clippy --all-targets -- -D warnings)
```

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -s -m "feat(desktop): LAN transport pump + Nearby event + settings plumbing"
```

---

### Task 10: Settings toggle UI

**Files:**
- Modify: `apps/fetchit-desktop/src/settings.ts`
- Create: `apps/fetchit-desktop/src/__tests__/settings.lan.test.ts`

- [ ] **Step 1: Failing test**

```ts
import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderSettings } from "../settings";

describe("settings — LAN delivery toggle", () => {
  beforeEach(() => { /* stub window.__TAURI__.core.invoke */ });

  it("reads lan_direct_enabled and reflects it in the checkbox", async () => { /* … */ });
  it("toggling the checkbox calls set_lan_direct_enabled", async () => { /* … */ });
});
```

- [ ] **Step 2: Run — confirm fail**

`(cd apps/fetchit-desktop && npm run test:run -- settings.lan)`
Expected: failure (UI not wired).

- [ ] **Step 3: Implement**

In `settings.ts`, add a `Network → Enable LAN delivery
(experimental)` checkbox alongside the existing peers editor.
Wire to `invoke("lan_direct_enabled")` and
`invoke("set_lan_direct_enabled", { enabled })`.

Help line: *"Send chat directly between devices on the same network.
Falls back to relay automatically."*

- [ ] **Step 4: Run — confirm pass**

`(cd apps/fetchit-desktop && npm run test:run -- settings.lan)`

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -s -m "feat(desktop): Settings toggle for LAN delivery"
```

---

### Task 11: Nearby section in the sidebar

**Files:**
- Modify: `apps/fetchit-desktop/src/chat/state.ts`
- Modify: `apps/fetchit-desktop/src/chat/sidebar.ts`
- Modify: `apps/fetchit-desktop/src/chat/panel.ts`
- Create: `apps/fetchit-desktop/src/chat/__tests__/nearby.test.ts`

- [ ] **Step 1: Failing tests**

```ts
describe("Nearby section", () => {
  it("renders nothing when nearbyPeers is empty", () => { /* … */ });
  it("renders one row per nearby peer not already in contacts", () => { /* … */ });
  it("filters out AgentIds that are already known contacts", () => { /* … */ });
  it("clicking Add opens the Add-contact dialog with the AgentId hint", () => { /* … */ });
});
```

- [ ] **Step 2: Run — confirm fail**

`(cd apps/fetchit-desktop && npm run test:run -- nearby)`

- [ ] **Step 3: Implement**

In `state.ts`, add `nearbyPeers: Map<string, NearbyPeerInfo>` and
a setter. Subscribe `chat:nearby` in `panel.ts`. Render in
`sidebar.ts` as a section below conversations:

```
─ Nearby ─
abcd1234…ef90    [ Add ]
```

`Add` calls the existing `openAddContact({ hint })` flow — user
still pastes the share URI to actually trust the peer.

- [ ] **Step 4: Run — confirm pass**

`(cd apps/fetchit-desktop && npm run test:run -- nearby)`

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -s -m "feat(desktop): Nearby sidebar section surfaces LAN-announced peers"
```

---

### Task 12: Live two-peer integration test

**Files:**
- Create: `crates/fetchit-chat/tests/live_lan.rs`

- [ ] **Step 1: Test**

```rust
#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[tokio::test]
#[ignore]
async fn two_peers_on_loopback_exchange_dm_via_lan_direct_not_relay() {
    // Spin up two Clients with distinct data_dirs and signers.
    // Cross-import each other's share card. enable_lan_direct(true).
    // No relay configured. Send a DM A → B. Assert the receipt
    // carries `transport_name == "lan-direct"` and B's chat store
    // contains the decoded message.
}
```

- [ ] **Step 2: Run — confirm pass**

`cargo test -p fetchit-chat --test live_lan -- --ignored --nocapture`

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -s -m "test(chat): two-peer LAN-direct loopback integration test"
```

---

### Task 13: Docs

**Files:**
- Modify: `docs/SECURITY.md`
- Append: `private/test-checklist.md`

- [ ] **Step 1: SECURITY.md**

Add to the load-bearing-files list:

> **LAN-direct transport** — `crates/fetchit-chat/src/lan_direct_transport.rs`,
> `lan_noise.rs`, `lan_static.rs`. X25519 static keypair sealed at
> rest; bound to `agent_id` via an ML-DSA-65 signature exchanged on
> Noise XX msg2/msg3. Receivers verify against the ML-DSA pubkey on
> the local Contact record. Strangers on the LAN are silently
> ignored. No NAT traversal, no WAN. Disabled by default; opt in
> via Settings → Network.

- [ ] **Step 2: test-checklist.md**

Add a new section with two-laptop bring-up steps:
- Both peers on the same Wi-Fi, both run `fetchit-desktop`.
- Both flip Settings → Network → Enable LAN delivery.
- Cross-import each other's share URI.
- Pull the Wi-Fi cable on the relay path (block relay outbound)
  and confirm a DM still lands.
- Confirm the Nearby section shows the other peer when the
  contact card is *not* imported, and is empty once it is.

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -s -m "docs: LAN-direct transport entry in SECURITY.md + live checklist"
```

---

## Verification gate before PR

- `cargo fmt --all`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `(cd apps/fetchit-desktop/src-tauri && cargo clippy --all-targets -- -D warnings && cargo test)`
- `(cd apps/fetchit-desktop && npm run test:run)`
- `cargo test -p fetchit-chat --test live_lan -- --ignored` (local)
- Two-laptop manual run per `private/test-checklist.md`.
