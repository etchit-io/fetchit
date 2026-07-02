# M6 Linked Devices — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans per stage. Steps use checkbox (`- [ ]`) syntax.
> **GATE: Josh reviews this plan and gives an explicit GO before any stage starts. No M6 implementation (either box) before that go.**

**Goal:** One person = one account = up to 5 devices, each with its own keys and MLS leaf, bound under a user root derived from the 24-word phrase — per spec `docs/superpowers/specs/2026-07-02-m6-linked-devices-design.md` (APPROVED, Josh + Alice, all findings folded).

**Architecture:** user ML-DSA key (phrase-derived) signs per-device AgentCertificates; contacts pin the user key via PairRecord v4 (anti-rollback revisions) and fan DMs out per device; each device is its own TreeKEM leaf in every group; a private devices-group carries self-sync; sibling group admission via invite-free TreeKEM direct-add (admin case) or the recorded-at-join cert capability (member case, fork patch).

**Tech stack:** fetchit-chat engine (Rust), x0x-fork mobile-0.27 (daemon capability, M6.5b only), fetchit-ffi/uniffi 0.29, Android shell (Kotlin), desktop shell (Tauri/TS), fetchit-relay-server (v4 record acceptance), fetchit-bridge (fedi rebinding).

**Ownership legend:** [A] Alice-lead, [B] Bob-lead, [J] joint (both write, mutual cross-review). Every stage: feature branch → fmt/clippy/tests → cross-review → device-verify where UI-visible → merge. uniffi rule: any `chat_ffi.rs` touch lands doc + regenerated `.so`+`.kt` in ONE commit.

---

## Stage M6.0 — Pre-work / future-proofing (small, unblocks everything)

**Files:** `crates/fetchit-chat/src/pair.rs` (record version discipline — A),
`crates/fetchit-chat/src/messages.rs` + group member structs (`user_id_hex`
self-population — B), Android `strings.xml` + desktop copy (recovery-phrase
copy says "account" — B).

- [ ] [A] PairRecord gains `record_version` + reserved `user_id` slot, additive; v3 readers unaffected (contract fixtures updated).
- [ ] [B] Populate own `user_id_hex` in group member records from the fabric root once M6.1 lands (stub constant now, wired in M6.1 exit).
- [ ] [B] Copy audit: every recovery-phrase string says it restores "your account", never "this device". Android + desktop + docs.
- [ ] Exit gate: workspace tests green, no wire change visible to v3 peers.

## Stage M6.1 — User root + AgentCertificates [J: B drafts engine, A cross-reviews + co-owns custody]

**Entry criteria:** Josh GO; custody call closed (open position sent to Alice 2026-07-02: user seed in passphrase vault beside identity seed, derive-on-demand, zeroize after signing, never retained on `Client`; enroll/revoke re-prompts vault passphrase).

**Files:** new `crates/fetchit-chat/src/fabric.rs`; `crates/fetchit-chat/src/identity.rs` (re-export); vault storage in the existing local_store layout.

- [ ] Write failing tests: `user_key_derives_deterministically_from_seed`, `cert_roundtrip_verifies`, `cert_rejects_tampered_agent_id`, `cert_rejects_wrong_user_key`, `existing_phrase_reroots_to_user_key_without_changing_agent_id`.
- [ ] Implement: `UserKeypair::from_seed(&[u8;32])` (ML-DSA-65, same saorsa-pqc path as pair.rs); `AgentCertificate { user_id, agent_id, agent_mldsa_pub_b64, kem_pub_b64, added_at_s, cert_version, sig }` with JCS-canonical signing under new `SIGN_DOMAIN_CERT` (mirrors `SIGN_DOMAIN_PROFILE` discipline); `mint_agent_certificate(&UserKeypair, …)`, `verify_agent_certificate(&cert, user_pub) -> Result`.
- [ ] Re-root: on first M6 launch, derive user key from the existing phrase seed, self-certify the existing agent as device #1, persist cert. agent_id unchanged.
- [ ] Custody: user seed stored passphrase-encrypted; `with_user_key<F>(passphrase, f)` derive-use-zeroize helper; no long-lived field (extends task #277 scope).
- [ ] Exit gate: unit tests + fmt/clippy; Alice cross-review (crypto surface = sensitive run); `user_id_hex` self-population from M6.0 wired.

## Stage M6.2 — PairRecord v4 [A-LEAD; B cross-review + Box-B gate]

Alice owns schema + implementation per her review: user_id + user pubkey + devices[] (agent_id, kem, ml_dsa, cert, added_at) + monotonic `revision`, user-key-signed; canonical device #1 for v3 readers; certs are out-of-record only. **Hard req: anti-rollback** — persist last-seen revision per pinned user_id, reject `revision <= last-seen`. Relay accepts/serves v4. B deliverables:

- [ ] [B] Cross-review the schema + anti-rollback store (sensitive: wire + auth surface).
- [ ] [B] Box-B full-suite gate on her SHAs; contract fixtures both directions (v4 writer/v3 reader, v3 writer/v4 reader).

## Stage M6.3 — DM fanout + receipts [J: engine B, outbox semantics A]

**Files:** `crates/fetchit-chat/src/client.rs` (send path), `messages.rs`, outbox driver.

- [ ] Failing tests: fanout produces one outbox entry per listed device; inbound dedup by message id across device copies; receipt aggregation = any-device-delivered; **outbox drops entries for devices removed by a newer revision** (hard req).
- [ ] Implement: resolve pinned user's current device list → encrypt per-device KEM → N envelopes, stable message id; receive-side dedup keyed (sender user_id, message id); receipt layer above outbox (per-envelope claim/ack untouched).
- [ ] Exit gate: engine tests + wiremock multi-device; cross-review; no shell changes yet.

## Stage M6.4 — Enrollment (QR link-a-device) [B-LEAD FFI+Android, A desktop]

**Files:** `crates/fetchit-ffi/src/chat_ffi.rs` (enroll surface — lockstep regen), Android `chat/` (LinkDeviceActivity/flow, QR via existing ZXing plumbing), desktop `src/ui/` link-device modal.

- [ ] QR payload: `fetchit://link/v1/` + base64url JSON {agent_id, agent_mldsa_pub, kem_pub, nonce, exp} minted by the NEW device.
- [ ] Existing device: scan → show short-code confirm → vault-passphrase prompt → mint cert (M6.1) → publish record revision N+1 → devices-group invite (M6.6 dependency: stub behind trait until M6.6 lands).
- [ ] Both-shell UX per spec section IV; failing-path copy (expired QR, wrong account, cap=5 reached).
- [ ] Exit gate: device-verified on S22 + desktop (enroll a real second device); cross-review; APK + tauri build.

## Stage M6.5a — Sibling group admission, admin path + roster collapse [B-LEAD]

- [ ] KeyPackage handshake message kind over devices-group: sibling derives per-group KP (`prepare_member`) → ships to in-group device.
- [ ] In-group admin device calls x0xd TreeKEM direct-add (`POST /groups/:id/members`, `treekem_key_package_b64`); assert `secure_plane == TreeKem` first; sibling pulls Welcome (existing fetch path).
- [ ] Roster collapse in both shells: group members keyed by user_id, "N devices" in detail only; attribution per-user.
- [ ] Exit gate: device-verify — phone joins group, desktop lands in it automatically; cross-review.

## Stage M6.5b — Member sibling-add capability [J: fork patch, upstream offer]

**Files:** `x0x-fork` `src/server/mod.rs` (both gates), `src/groups/mod.rs` (member user binding).

- [ ] Member records carry `user_id` + cert at join (fills the `user_id: None` gap at groups/mod.rs:913).
- [ ] Sibling-add commit: member A adds agent B with cert_B; every receiver verifies cert_B chains to A's **recorded-at-join** user_id (defeats fabricated-user-key). Relax mint gate (server/mod.rs:11453) + distributed authority gate (8746-8751) for exactly this shape.
- [ ] Multi-daemon e2e (dogfood_local pattern); Alice cross-review (authority surface).
- [ ] Offer upstream on saorsa-labs/x0x referencing issue #91; carry as fork commit meanwhile.

## Stage M6.6 — Devices-group self-sync [J]

- [ ] Auto-create at first enrollment (invisible, invite_only, TreeKem); membership maintained by enroll/revoke.
- [ ] Sync payload kinds: contact ops, profile/settings, DM mirrors + read markers, group signals, KP handshake (M6.5a). Forward-only; no retroactive history (explicit non-goal).
- [ ] **Hard req (Alice finding 6):** wire the 0.27 returning-member rekey + epoch catch-up so an offline device re-syncs, never wedges; wedge test in CI (simulated offline epoch gap).
- [ ] Exit gate: two-device sync device-verified (add contact on phone → appears on desktop).

## Stage M6.7 — Revocation + phrase-only recovery [B-LEAD, A review]

- [ ] Revoke from surviving device: cert revocation entry, record revision bump, devices-group leaf removal + rekey, chat-group member-device removal.
- [ ] **Hard req (finding 5):** proactive revised-record push to active contacts + re-resolve TTL on cached device lists; residual window documented in SECURITY.md.
- [ ] Phrase-only recovery: re-derive user key → fresh device #1 → record supersedes (revision continuity per anti-rollback rules — define recovery revision semantics with Alice: recovery bumps past last-known via relay-stored latest revision).
- [ ] Exit gate: device-verify revoke (stolen-phone drill) + recover (wipe + phrase).

## Stage M6.8 — Fediverse rebinding [B-LEAD bridge, A review]

- [ ] Mint attestation binds handle ↔ actor URL ↔ **user_id**; bridge verifies any device whose cert chains to the user_id for publish/update; migration for the (pre-launch) existing attestation shape.
- [ ] Exit gate: publish a post from the second device; M5 lookup flows unchanged.

## Stage M6.9 — Verification matrix + soak [J, gates the milestone]

- [ ] Matrix on real hardware (S22 + desktop + droplet peer, cross-NAT/CGNAT): enroll · both-devices-live DM both directions · group join with auto sibling admission · sync (contact add, read state) · revoke + delivery stops (bounded window measured) · phrase recovery · cap enforcement.
- [ ] Multi-day soak on the fleet (wyse + droplets) with a 2-device headless user (extends #254 harness).
- [ ] Docs: ARCHITECTURE.md fabric section (arch-stamps), SECURITY.md threat-model deltas, honest-claims update.

## Sequencing + parallelism

M6.0 → M6.1 → {M6.2 [A] ∥ M6.4-prep [B]} → M6.3 → M6.4 → {M6.5a ∥ M6.6} → M6.5b → M6.7 → M6.8 → M6.9. Alice's M6.2 runs parallel to my M6.4 UI prep after M6.1; M6.5b (fork patch) can start any time after M6.1 since it only needs the cert shape.

## Standing risks

x0x upstream moves daily — re-check for fabric-adjacent landings (esp. #91, #130) at each stage start; devices-group wedge is the highest-severity failure (finding 6 test is non-negotiable); fanout cost data collected at M6.3 to validate cap=5.
