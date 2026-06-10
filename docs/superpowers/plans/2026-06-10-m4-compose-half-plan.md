# M4 compose half - desktop implementation plan

> Executes spec sections 3.4 + 3.5 (publish command) of
> `docs/superpowers/specs/2026-06-08-chat-ui-excellence-m4-pane-design.md`.
> Read feed (3.2/3.3) already shipped. Inline TDD execution; each task is
> failing test, minimal impl, green, DCO commit.

**Goal:** compose + publish public posts from the fediverse pane, with the
mandatory confirmation modal, actor-mint onboarding, and reply-publicly on
feed cards.

**Crate facts (verified):** `Client::publish_public_post(handle, passphrase,
&PublicPost)` exists and the fediverse transport is wired by
`Client::builder().build()` (client.rs:1835); `Client::mint_actor_identity
(handle, domain, passphrase)` validates `[A-Za-z0-9_-]{1,64}`. No crate
changes; Bob's lane untouched.

**Desktop-owned decisions:**
- The active handle lives in desktop `Settings.fediverse_handle` (empty =
  not minted). The crate vault stores per-handle key material; the desktop
  stores which handle is active. Single-handle UX for v1.0.
- `DEFAULT_FEDI_DOMAIN = "etchit.io"` const in the commands module; the
  bridge relay will serve WebFinger for it (Bob lane). Revisit when domains
  land.
- Mentions extracted backend-side from `body_md` whitespace tokens via
  `fetchit_fedi::parse_mention` so the frontend stays dumb.

### Task 1 - src-tauri fediverse commands
Files: create `src-tauri/src/fediverse.rs`; modify `settings.rs`
(`fediverse_handle` serde-default field), `lib.rs` (mod + 3 handlers).
- `fediverse_actor_status() -> Option<String>` (handle from settings)
- `fediverse_mint(handle) -> String` (mint via Client, persist handle,
  return actor_url; chat-flag gated)
- `fediverse_publish(body_md, reply_to_actor_url?) -> PublishReportDto
  {delivered: Vec<String>, failed: Vec<(String,String)>}` (builds
  PublicPost with extracted mentions + now-ms; chat-flag gated)
- helper `extract_mentions(&str) -> Vec<String>` + unit tests (plain
  token, punctuation-trailing, dedup, non-mention `@` noise)
Tests: extract_mentions table; settings field default round-trip.

### Task 2 - compose.ts (+ tests)
Files: create `src/fediverse/compose.ts`, `compose.test.ts`; extend
`src/fediverse/styles.css`.
- `mountCompose(host, opts): ComposeApi {setReplyTo, clear, element}`
- Not-minted state: handle input (client-side mirror of the crate
  validator) + "create public handle" button -> `fediverse_mint` ->
  swap to composer.
- Composer: textarea + "Post publicly" button + public framing line.
- Mandatory confirm modal, spec copy verbatim: "Post publicly to the
  fediverse. This is visible to operators, instance admins, and any
  subscriber of your actor. Anyone you mention can see it; your
  community denylist is the only filter." Buttons "Post publicly" /
  "Cancel" + session-scoped "Don't ask again for this session".
- Reply chip: `setReplyTo(actorUrl)` renders "replying publicly to
  <url>" + clear (x); passes `reply_to_actor_url` on publish.
- Result line from PublishReport ("delivered N / failed M") - honest,
  no fake success.
Tests: mint flow renders + invokes; modal gates invoke (no backend call
until accept); cancel aborts; don't-ask-again skips modal within
session (exported reset for tests); reply chip set/clear threads
reply_to_actor_url; textarea clears on success.

### Task 3 - reply-publicly on feed cards + panel wiring
Files: modify `src/fediverse/feedPost.ts` (+test), `feed.ts`,
`panel.ts` (+test), `styles.css`.
- feedPost gains a "reply publicly" affordance invoking
  `onReply(verifiedActorUrl)` - attribution source, never body actor.
- feed threads `onReply` through; panel mounts compose under the feed
  and wires `onReply -> compose.setReplyTo`.
Tests: card exposes the affordance; callback receives
verified_actor_url even when body asserts a different actor; panel
prefills compose on reply click.

### Gates per task
`cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test`
(src-tauri, from its dir) for Task 1; `npx tsc --noEmit && npm run
test:run` for Tasks 2-3; DCO sign-off every commit.
