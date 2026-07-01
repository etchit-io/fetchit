# LIT Chat UI Excellence + M4 Fediverse Pane - Design

**Status:** design spec, approved-in-brainstorm (2026-06-08), pending written-spec review. Terminal state is the writing-plans handoff (one plan per workstream).

**Goal:** Bring the desktop LIT Chat surface to best-in-class (Signal / iMessage / Telegram tier) and ship the M4 Fediverse pane in full (read feed + compose + in-app reply), without weakening any privacy, honesty, or modularity invariant the app already holds.

**Architecture:** Evolve the existing "terminal-warm" copper-on-ink identity rather than reinvent it. Three independently-shippable workstreams over a shared token + brand foundation: (1) a Visual Identity system (branded `>`-motif logo marks for the Fetch / Etch / LIT family plus a UI icon set), (2) Chat Message UX (emoji, reactions, markdown, inline images, reply/quote, preview cards, typing), and (3) the M4 Fediverse desktop pane consuming the already-built bridge backend. Each workstream gets its own implementation plan.

**Tech stack:** Vanilla TS + Vite frontend (no framework), per-concern modules under `apps/fetchit-desktop/src/`. CSS custom-property token system in `src/styles.css` + `src/chat/styles.css`. Rust/Tauri backend in `src-tauri/` for the event bridge. SVG assets inline (no icon font, no external asset CDN). No new runtime dependencies unless named below.

---

## Why one spec, three workstreams

The three surfaces share a single design language (tokens, motion, the `>` motif), and they cross-reference: the icon set from Workstream 1 is consumed by the Workstream 2 composer and the Workstream 3 pane chrome. Keeping the foundation and constraints in one document is DRY and prevents drift. But each workstream produces working, testable software on its own and has a distinct backend-dependency profile, so each becomes its own implementation plan:

| Workstream | Ships independently because | Backend dependency |
|---|---|---|
| 1. Visual Identity | Pure frontend asset + CSS work; nothing else blocks on it, everything else looks better with it | none |
| 2. Chat Message UX | Each feature (emoji, markdown, reply, images, preview, typing) is its own additive PR | reactions + typing need a Bob-owned sealed wire signal; the rest is frontend-only |
| 3. M4 Fediverse Pane | Read-feed half consumes an existing broadcast channel; compose half is a separate PR | read = `subscribe_to_public_posts()` (built); compose = `publish_public_post` + handle mint (Bob, impl-plan Stages 1-5) |

Build order across workstreams is in the Phasing section. Within a workstream, order is listed in that workstream's section.

---

## Foundation (what exists - evolve, do not reinvent)

Grounded in the current code. The spec builds on these, it does not replace them.

**Token system.** `apps/fetchit-desktop/src/styles.css:13-66` declares the theme tokens for three themes (`dark` default, `dim`, `light`) on `:root` / `body[data-theme="..."]`. Canonical contract is `docs/BRAND.md`, kept in lockstep with etch>it. Load-bearing tokens: `--ink #0a0a0a`, `--ink-2`, `--line`, `--bone #f5f2eb`, `--bone-dim`, `--ash`, `--copper #c9732b`, `--copper-bright`, `--rust`, `--signal-ok`. Motion: `--ease-out-expo: cubic-bezier(0.16,1,0.3,1)`, `--dur-micro 160ms`, `--dur-trans 280ms`, `--dur-enter 720ms`. Rule from BRAND.md: never introduce hex literals in CSS rules, never read theme by hex in JS, add new tokens to both apps in lockstep.

**Typography.** System UI font for chrome (`14px/1.5 ui-sans-serif, system-ui, ...`); JetBrains Mono / Source Code Pro for address/code/hex. Canonical scale table in BRAND.md (page heading 22/600, section 15/600, body 14/400, helper 12/400 ash, wordmark 18/700 mono, icon-button glyph 18/400). Any new size goes in the BRAND.md table first.

**Chat overlay.** `mountChatPanel(host, handlers)` (`src/chat/panel.ts:58`) mounts into `#chat-panel` (`index.html:35`). It is a fixed overlay, `z-index: 50`, that docks right at `--chat-dock-width: 460px` via `.chat-panel--docked` + `body.chat-docked` (`src/chat/styles.css:4-42`), with a `chat-slide` enter animation. It is NOT a tab. Wired into `src/controller.ts:126`.

**Per-concern chat modules** (`src/chat/`): `panel.ts` (mount + open/close/dock), `sidebar.ts` (conversation list, unread badges, `iconButton("＋"...)`), `conversation.ts` (header + keyed-diff message stream + composer host, `ConversationHandle`), `bubble.ts` (`renderBubble` + `bubbleRenderKey`), `composer.ts` (`mountComposer` → textarea + Send, Enter sends / Shift+Enter newline, auto-grow to ~6 rows), `bubblePreview.ts` (`mountAutonomiPreview` lazy autonomi:// cards that reuse reader renderers). State + store live alongside.

**Reader renderer pipeline.** `src/types.ts` is the `Rendition` union (lowercase kinds: `text`, `etchitEnvelope`, `json`, `tabular`, `archive`, `html`, `image`, `audio`, `video`, `pdf`, `binary`, `blocked`), mirroring the Rust `#[non_exhaustive]` enum in `crates/fetchit-core/src/handler.rs`. `src/renderers/<kind>.ts` exports `render{Kind}(r, into)`; `src/renderers/dispatch.ts` switches on `r.kind` with a `never`-exhaustiveness guard. `bubblePreview.ts` already reuses `renderText` / `renderJson` / `renderImage` / `renderTabular` / `renderEtchitEnvelope` for lightweight inline previews and falls back to "Open in reader" for heavy kinds.

**Existing vector language.** The mascot-dog (`src/ui/mascot.ts:215-329`) is a hand-coded inline SVG scene, CSS-animated and theme-aware (`fill: var(--copper)`, `stroke: var(--bone)`). It is the proof that a coherent copper-on-ink vector identity already lives in the app and that inline-SVG-driven-by-tokens is the established pattern. The wordmark is live text `fetch<span>></span>it` with a copper `>` (`index.html:14`, styled `#mark span { color: var(--copper) }` at `styles.css:147-158`).

**What does NOT exist yet:** any branded logo-mark SVG (only generic raster app icons in `src-tauri/icons/`), any UI icon set (affordances today are unicode glyphs: `💬 ⚙ ★ ▦ ←` in the header, `＋ ⌗ ↪` in the sidebar, `"Send"` as text), emoji/reactions, markdown rendering in bubbles, inline images, reply/quote, typing indicators, and any desktop Fediverse surface.

---

## Cross-cutting constraints

These bind every workstream. A PR that violates one is not done.

1. **Sealed-by-default (M2 discipline).** Any new message-borne content (reactions, inline images, typing signals if they ride the message path) travels inside the sealed envelope. No plaintext-on-relay payload, no metadata side channel. Where a feature needs a new wire signal, the wire is Bob's lane and this spec defines the UI contract against an agreed interface (see Workstream 2.2, 2.7).
2. **Honesty floor (M0).** The "⚠ unverified sender" affordance stays. There is NO positive "verified" badge anywhere. Fediverse content is attributed only to the relay-verified `verified_actor_url`, never to the activity body's self-asserted actor, and is labelled as observably-public / non-PQ (see Workstream 3).
3. **Untrusted content is untrusted.** Markdown bodies (Workstream 2.3) and ActivityPub `activity_json` (Workstream 3.3) are untrusted input. Sanitize and escape; never inject raw HTML into the chat DOM. Reuse the app's existing sanitization posture; do not hand-roll a second one.
4. **Modular, one concern per file.** New features land as new `src/chat/*.ts` (or `src/fediverse/*.ts`) modules, not as growth of `panel.ts` / `conversation.ts`. CSS lands in the matching surface stylesheet using BEM-ish class names, using tokens only.
5. **Brand form.** Wordmarks (`fetch>it`, `etch/it`, `LIT Chat`) appear in user-facing copy only; code identifiers stay generic (`fetchit`, `etchit`, `chat`). New tokens or type sizes are added to `docs/BRAND.md` in lockstep with etch>it before use.
6. **Idiot-proof main flow.** The common path stays obvious; power and privacy-tradeoff toggles (typing-on, etc.) live in Settings. Risk copy is specific, never vague.
7. **Public-artifact discipline.** Commits implementing this spec are DCO-signed via `59794857+josh-clsn@users.noreply.github.com`, carry no Co-Authored-By trailer, and avoid em-dashes. CI gate (`cargo fmt` + `clippy --workspace -D warnings` + `cargo test --workspace`; desktop `npm run test:run` + `cd src-tauri && cargo test`) is green per step.

---

## Workstream 1 - Visual Identity System

A coherent, launch-grade vector identity: the brand marks plus the working UI icon set, all copper-on-ink, all theme-aware, all inline SVG driven by `currentColor` so a single asset works across the three themes.

### 1.1 The `>` motif and the logo-mark family

The `>` chevron is the through-line of the ecosystem (fetch**>**it; the etch**/**it slash is its sibling). Design one coherent mark family:

- **fetch>it mark** - the reader. The `>` as forward-motion / retrieval.
- **etch/it mark** - the publisher. The `/` as inscription. Sibling weight and grid to the fetch>it mark (these are reused in etch>it; design them as one ecosystem family per the brand bible).
- **LIT Chat mark** - the chat surface (LIT = Liberty-it). The spark/flame reading of "lit" rendered in the same geometric copper-on-ink language, carrying a quiet trust connotation (the sealed/PQ surface) without a loud "secure" banner.

Constraints: single-accent copper on ink, geometric, legible at 16px, built on one shared grid and stroke weight. Each mark ships as a single inline SVG using `fill="currentColor"` / `stroke="currentColor"` (NO hardcoded hex) so it inherits `--copper` / `--bone` by context and recolors automatically on theme switch, exactly like the mascot. Provide each at the sizes the app actually consumes (see 1.3); do not pre-generate a raster pyramid the app never references.

The header wordmark stays live text (`#mark`) for crispness and copy-paste; the logo mark is an additional asset used where a glyph is wanted (window/taskbar identity, an About panel, the chat pane header, the empty-state). App-icon rasterization (replacing the generic `src-tauri/icons/*`) is a downstream packaging step, called out in Phasing, not blocking the in-app work.

### 1.2 UI icon set

Replace the ad-hoc unicode glyphs with a small, consistent inline-SVG icon set on the same 24px grid and stroke weight. Minimum set for v1.0:

`chat`, `fediverse` (the pane), `send` (a `>`-derived send glyph, retiring the `"Send"` text label or pairing with it), `attach`, `emoji` / `react`, `reply`, `close`, `dock`, `settings`, `add-contact`, `new-group`, `join-group`, `image`, plus the standalone `>` glyph for separators/breadcrumbs. Each is theme-aware via `currentColor` and sized by its button container per the BRAND.md "icon button glyph" row (18px in the glyph slot, button container drives final size).

### 1.3 Asset format and delivery

- **One inline SVG sprite module**, `src/ui/icons.ts`, exporting an `icon(name): SVGElement` helper (or `icon(name): string` of sanitized markup) plus the logo marks. This mirrors the mascot's inline-SVG-string pattern and keeps assets versioned in code, theme-reactive, and free of network fetches. No icon font (hinting/encoding baggage), no `<img src>` to files (defeats `currentColor` theming and adds load states).
- Icons reference only `currentColor`; color comes from the surrounding element's `color` token. State color (hover copper-bright, disabled ash) is CSS on the container, not baked into the asset.
- Accessibility: every icon-only control carries an `aria-label`; decorative marks are `aria-hidden`.

### 1.4 Token + scale evolution

Evolution, not churn. Anticipated additions, each added to `docs/BRAND.md` and both apps' `styles.css` in lockstep before use:

- An elevated-bubble / reaction-chip surface token if `--ink-2` proves insufficient for the outgoing-bubble + reaction-pill layering (decide during implementation; prefer reusing `--ink-2` / `--line`).
- An icon-stroke-weight custom property if the icon set needs a single tunable weight.
- Any new type size (e.g. a reaction-count micro size) goes in the BRAND.md scale table first.

No new accent hue. Copper stays the single accent across all three workstreams.

### 1.5 Files and boundaries

- Create: `src/ui/icons.ts` (icon + logo-mark inline-SVG module).
- Create: `src/ui/icons.css` or a section in `styles.css` for icon/mark sizing + state colors.
- Modify (consume the set, retire glyphs): `src/chat/sidebar.ts` (`iconButton` glyphs), `src/chat/composer.ts` (Send), `index.html` + `src/controller.ts` (header buttons), and the Workstream 2/3 modules as they land.
- Source-of-truth doc: append the icon/mark inventory + grid/weight rules to `docs/BRAND.md`.

### 1.6 Testing

- Vitest: `icon(name)` returns an `<svg>` with no hardcoded hex (assert no `#` color literals; only `currentColor`), correct `viewBox`, and an accessible label hook.
- Vitest: every icon name the chat/pane code references resolves (no missing-icon gaps); a render smoke test that mounting a button with each icon does not throw.
- Manual acceptance (BRAND.md acceptance check): toggle all three themes, confirm marks + icons recolor in lockstep with chrome.

---

## Workstream 2 - Chat Message UX

Make the bubble + composer surface feel first-class. Every feature is additive and independently shippable.

### 2.1 Composer evolution

Evolve `src/chat/composer.ts` (today: textarea + Send) into a composer with an action row: emoji button, attach button, Send-as-icon. Keep the existing keyboard contract (Enter sends, Shift+Enter newline, auto-grow). The composer stays one module; the emoji picker and attach flow are their own modules it mounts.

- Create: `src/chat/emojiPicker.ts` - a lightweight, local, categorized emoji picker (Unicode emoji; no remote asset, no third-party API, consistent with the dropped-GIF-search privacy decision). Inserts at caret.
- Attach: a file picker that produces a sealed inline-image message (see 2.4). Scope attach to images for v1.0; other file types are out of scope.

### 2.2 Reactions (UI = Alice, wire = Bob, sealed)

Message reactions (tap an emoji onto a bubble). Split by lane:

- **Wire (Bob).** A reaction is a sealed message referencing a target message id + an emoji, carried inside the existing sealed envelope (no plaintext-on-relay, no side channel). Bob owns the envelope addition and the apply/aggregate semantics in `fetchit-chat`. This spec depends on, and does not define, that wire format; it defines the UI contract: the chat client exposes inbound reactions as an aggregated map per message (`{ emoji: count, mine: bool }`) on the same event stream pattern as receipts/presence, and accepts an outbound `react(messageId, emoji, on/off)` call.
- **UI (Alice).** A reaction affordance on hover/long-press of a bubble; a reaction pill row under the bubble showing aggregated counts with the user's own reactions highlighted (copper); optimistic local echo with reconcile on delivery. Renders in `src/chat/bubble.ts` (the pill row is part of the bubble) sourced from store state; `bubbleRenderKey` extends to include a reaction fingerprint so the keyed diff in `conversation.ts` re-renders a bubble when its reactions change.

If Bob's wire is not ready when the rest of Workstream 2 ships, the UI lands behind the agreed interface against a stub and energizes when the wire merges.

### 2.3 Markdown styling

A tasteful, safe markdown subset in received and sent bubbles: bold, italic, strikethrough, inline `code`, fenced code blocks (reuse the reader's syntax highlighter `src/renderers/syntax.ts` via the existing `code-block` pattern), links (rendered as the existing autonomi/x0x/fetchit-aware link handling in `bubble.ts`), blockquote, lists. NOT a full CommonMark surface, NOT raw HTML.

- Create: `src/chat/markdown.ts` - parse the subset to a sanitized DOM fragment. Untrusted input: escape first, then apply the allowed inline/block transforms; never set `innerHTML` from message text. Links go through the existing link-detection path so denylist/preview behavior is preserved.
- Modify: `src/chat/bubble.ts` to render body via `markdown.ts` instead of plain text.

### 2.4 Inline images (sealed, lazy)

Inline image messages, sealed like any other message, lazy by the project's media discipline (no preload, no full-chunk-per-probe, render on explicit reveal or when cheap).

- Outbound: the composer attach flow seals the image bytes through the existing media path; the bubble shows a bounded thumbnail.
- Inbound: render a bounded, lazy thumbnail in the bubble; click opens full view. Reuse `src/renderers/image.ts` for the actual decode/display so there is one image renderer.
- Wire/seal of image bytes is the existing sealed-media path (Bob's lane if a new envelope shape is needed); UI defines the bubble treatment.

### 2.5 Reply / quote

Reply-to-message: a quoted snippet of the parent above the reply, tap-to-scroll to the parent.

- Create: `src/chat/reply.ts` - the quoted-parent preview element + the composer reply-context bar (shows what you are replying to, with a clear cancel).
- The reply linkage (parent message id) rides the sealed message (Bob's lane for the envelope field; UI consumes a `replyTo` id on the message). `bubble.ts` renders the quoted parent from store lookup; missing-parent degrades gracefully to "original message unavailable".

### 2.6 autonomi:// preview cards (extend existing)

`src/chat/bubblePreview.ts` already renders lazy autonomi:// cards reusing reader renderers. Extend, do not rewrite:

- Richer card chrome (title/type/size affordance using the Workstream 1 icon set) while keeping the lazy-by-default fetch (nothing fetched until the user clicks Preview).
- Confirm the heavy-kind fallback ("Open in reader") still routes through `handlers.onOpen`. No new fetch-on-render.

### 2.7 Typing indicators (ship, default OFF)

Ship typing indicators, default OFF, opt-in in Settings, because a typing signal is a metadata emission and the honest default is silence.

- **Setting:** a Settings → Chat (or Privacy) toggle `typing-indicators` defaulting to off; persisted like the existing theme/dock prefs (localStorage), with specific risk copy ("Sharing typing status reveals when you are composing to the people in this conversation").
- **Wire (Bob).** When enabled, a typing signal rides the presence-adjacent path (the existing `WatchPresence` / `PresenceUpdate` machinery is the natural home), gated by the setting so OFF emits nothing. UI contract: a per-conversation `peerTyping` boolean on the presence event stream; an outbound `setTyping(convId, bool)` the composer calls (debounced) only when the setting is on.
- **UI (Alice).** A typing affordance in the conversation header/stream footer, sourced from store state. Create `src/chat/typing.ts` for the indicator element + the debounce logic.

### 2.8 Files and boundaries

- Create: `src/chat/emojiPicker.ts`, `src/chat/markdown.ts`, `src/chat/reply.ts`, `src/chat/typing.ts`.
- Modify: `src/chat/composer.ts` (action row, emoji/attach mounts, send icon), `src/chat/bubble.ts` (markdown body, reaction pills, quoted-parent, image thumbnails, `bubbleRenderKey` extension), `src/chat/conversation.ts` (typing footer host; keyed-diff already handles re-render via `bubbleRenderKey`), `src/chat/styles.css` (all new surfaces, tokens only), Settings module (typing toggle).
- Backend contracts consumed (Bob's lane, defined as interfaces here): sealed reaction wire + aggregate, `replyTo` envelope field, sealed inline-image path if new, typing-over-presence signal. Each lands behind its interface so the UI is not blocked.

### 2.9 Testing

- Vitest per module: emoji insert-at-caret; markdown subset renders bold/italic/code/links and ESCAPES a hostile `<script>`/`<img onerror>` payload (the security-critical test); reply context bar set/cancel; reaction pill aggregation + own-reaction highlight + `bubbleRenderKey` changes when reactions change; typing indicator shows only when the setting is on and the peer signal is true.
- Reuse existing `conversation.ts` keyed-diff tests; add cases for reaction/typing-driven re-render.
- No network in unit tests (project rule); the sealed-wire pieces are tested at the `fetchit-chat` layer by Bob.

---

## Workstream 3 - M4 Fediverse Desktop Pane

The desktop UI for the M4 bridge. The bridge backend (WebFinger handle, ActivityPub transport, inbox, denylist `EntryKind::ActorUrl`, `EnvelopeKind::PublicPost`) is designed and largely built per `docs/superpowers/plans/2026-06-07-m4-fediverse-{brainstorm,impl-plan}.md` (Bob's lane). This workstream is the desktop surface only and must not re-litigate the protocol.

### 3.1 What is already built (do not duplicate)

From the codebase recon:

- `crates/fetchit-relay-proto/src/public_post.rs` - `PublicPostPayload { verified_actor_url, activity_json }`, bridge sentinels, `TransitEnvelope::public_post(...)`.
- `crates/fetchit-relay-proto/src/envelope.rs` - `EnvelopeKind::PublicPost` (unsealed by design; attribution rides the wrapper, never chat-layer crypto).
- `crates/fetchit-relay-server/src/inbox/{sink,operator}.rs` - denylist-gated `SessionBroadcastSink` (canonicalizes actor URL via `EntryKind::ActorUrl` before broadcast), `FediverseWebFinger`, `DenylistConsumerCheck`, `FETCHIT_FEDIVERSE_INBOX` gate.
- `crates/fetchit-chat/src/client.rs` - `PublicPostDelivery { verified_actor_url, activity_json }`, a `public_post_tx` broadcast channel, `Client::subscribe_to_public_posts()`, `Client::dispatch_inbound_public_post()`.

**Built shape supersedes the impl-plan sketch.** The impl-plan Stage 5 sketched a parsed `PublicPost { author_handle, body_md, ... }`; the code settled on `PublicPostDelivery { verified_actor_url, activity_json }` carrying raw untrusted ActivityPub JSON-LD plus the relay-verified actor URL. The desktop parses `activity_json` client-side and attributes only to `verified_actor_url`. (Flag for Bob/Josh: confirm this is the intended final inbound shape, and that `subscribe_to_public_posts()` actually emits end-to-end. `relay_transport.rs` carried a "no chat-layer route until Stage 5.3" drop; the read pane depends on that route being live.)

### 3.2 Placement-agnostic feed component

Build the feed as a **placement-agnostic component** with two mount targets (decision locked in brainstorm: default standalone, user-selectable in-chat):

- **Default:** a standalone overlay `#fediverse-panel`, mirroring the chat overlay pattern exactly (`mountChatPanel` is the template): fixed, own z-index, header with the Workstream 1 `fediverse` mark + close/dock, its own concerns split into modules, its own stylesheet `src/fediverse/styles.css`.
- **Opt-in (Settings):** folded into the chat sidebar as a pinned "Feed" item that renders the same component inline.

The component does not know which host it is in; the host (overlay vs sidebar-fold) is chosen by a Settings pref and passed at mount. Create `src/fediverse/panel.ts` (`mountFediversePanel(host, opts)`), `src/fediverse/feed.ts` (the scrolling post list with the same keyed-diff discipline as `conversation.ts`).

### 3.3 feedPost card renderer (untrusted activity_json)

A post card renderer for `PublicPostDelivery`. This is the security-critical surface of the workstream.

- Create: `src/fediverse/feedPost.ts` - parse `activity_json` (ActivityPub `Create{Note}` or `Note`), extract display fields (content, published time, attachments, in-reply-to), render a card. Untrusted: sanitize/escape the `content` (reuse the app sanitization posture, same as Workstream 2.3 markdown; never `innerHTML` raw fediverse HTML). Attribute the card to `verified_actor_url` ONLY, never to the activity's self-asserted `actor`/`attributedTo`.
- Honesty chrome: a distinct "from fediverse" badge and the "⚠ observably public, non-PQ" framing. NO positive verified badge. The card visibly reads as the third privacy contract (C = Public), distinct from sealed DMs/groups.
- Decision: the feed renders its own card type (`feedPost.ts`); it does NOT add a `Rendition` variant to the reader pipeline. The reader pipeline is address → bytes → Rendition; a fediverse post arrives via the broadcast channel, not an address fetch. (This refines the brainstorm assumption that #344 would be a new `Rendition` kind; the built `PublicPostDelivery` broadcast seam makes a dedicated feed renderer the correct, cleaner boundary. Flagged for review.)

### 3.4 Compose public post + confirmation modal

The "full pane" includes compose + in-app reply (Josh: ship full, not publish-only). This realizes the impl-plan Stage 5 UI requirement that was deferred ("UI confirmation flow ships behind a TODO + tracking issue when the chat backend lands").

- Create: `src/fediverse/compose.ts` - a public-post composer (reusing the Workstream 2 composer chrome where sensible) and the in-app reply affordance on a feed card (reply-public is the ONLY reply option for a fediverse-sourced post; no backchannel to DMs).
- **Mandatory confirmation modal on publish** (impl-plan Alice [E]): "Post publicly to the fediverse. This is visible to operators, instance admins, and any subscriber of your actor. Anyone you mention can see it; your community denylist is the only filter." Buttons: "Post publicly" (primary), "Cancel". Tickbox: "Don't ask again for this session" (session-scoped, not cross-session). The UI gates the call; the chat API does not pop the modal.
- Backend dependency: compose calls `Client::publish_public_post` (impl-plan Stage 5.2) and requires a minted WebFinger handle (Stages 1-2, 6). Compose is therefore phased AFTER the read feed (3.2/3.3), which only needs `subscribe_to_public_posts()`. If publish is not yet built, the read feed ships first and compose follows.

### 3.5 Event bridge (Rust/Tauri)

Mirror the existing chat event bridge (`chat:presence` / `chat:receipt`, Tasks #131-#136). Add:

- A Tauri command to start the public-post subscription and a `chat:public-post` (or `fediverse:post`) event emitting `PublicPostDelivery` payloads to the frontend, bridging `Client::subscribe_to_public_posts()` (Rust broadcast) → window event. Lives beside the existing chat event wiring in `src-tauri/src/`.
- A Tauri command for `publish_public_post` (compose), gated identically to the existing chat send commands.

### 3.6 Files and boundaries

- Create (frontend): `src/fediverse/panel.ts`, `src/fediverse/feed.ts`, `src/fediverse/feedPost.ts`, `src/fediverse/compose.ts`, `src/fediverse/styles.css`.
- Modify (frontend): `src/controller.ts` (mount the pane, wire the open affordance + Settings placement pref), Settings module (default-standalone / opt-in-fold toggle), `index.html` (the `#fediverse-panel` host + a header entry point using the `fediverse` mark).
- Modify (backend): `src-tauri/src/` chat event module (public-post subscription command + event; publish command).
- Consume (Bob's lane, do not modify here): `crates/fetchit-chat` public-post API, `crates/fetchit-relay-*` bridge. Reference the M4 impl-plan; do not duplicate its backend tasks.

### 3.7 Testing

- Vitest (security-critical): `feedPost.ts` parses a representative ActivityPub `Create{Note}` fixture and renders content; a hostile `content` (`<script>`, `<img onerror>`, javascript: URL) is escaped/neutralized; attribution renders `verified_actor_url` and IGNORES a mismatched self-asserted `actor` in the body.
- Vitest: the placement-agnostic component mounts in both hosts (overlay + sidebar-fold) from the same factory; feed keyed-diff adds/updates posts without full re-render.
- Vitest: publish path does not call the backend until the confirmation modal is accepted; "don't ask again" is session-scoped.
- Backend: `src-tauri` cargo test for the event-bridge command shape (subscription emits, publish command gating). The bridge protocol itself is tested at the `fetchit-chat`/relay layer by Bob.

---

## Phasing (cross-workstream build order)

Each phase is a shippable increment. Within a workstream, follow that workstream's section order.

1. **Workstream 1 first (foundation).** The icon set + marks unblock the visual quality of everything after and have zero backend dependency. Ship `src/ui/icons.ts` + retire the header/sidebar/composer unicode glyphs.
2. **Workstream 2, frontend-only features.** Markdown (2.3), preview-card polish (2.6), composer chrome + emoji (2.1) land without any Bob dependency, consuming Workstream 1 icons.
3. **Workstream 3 read feed (3.1-3.3, 3.5 read half).** Consumes the built `subscribe_to_public_posts()`; high user-visible value; verify the inbound route is live first.
4. **Workstream 2 wire-dependent features.** Reactions (2.2), reply (2.5), inline images (2.4), typing (2.7) energize as Bob's sealed-wire interfaces merge; UI lands behind the interfaces ahead of the wire where useful.
5. **Workstream 3 compose half (3.4, 3.5 publish half).** Depends on `publish_public_post` + handle mint (impl-plan Stages 1-2, 6).
6. **Packaging tail.** Rasterize the new marks into `src-tauri/icons/*` (replace the generic defaults) and refresh the Tauri/window identity. Update `docs/BRAND.md` with the final mark/icon inventory.

Workstreams 1 and 2-frontend can proceed in parallel with Bob's M4 backend work; nothing in this spec blocks his impl-plan stages, and his stages gate only the wire-dependent leaves above.

---

## Out of scope (v1.0)

- Third-party GIF search (Giphy/Tenor). Dropped: leaks IP + queries to a third party, wrong tradeoff for the privacy wedge. Custom image paste/attach (sealed, no third party) is in scope (2.4); revisit relay-proxied GIF search post-launch only on real demand.
- Voice messages, message edit/unsend, threaded replies (flat reply/quote only in 2.5).
- Fetchit acting as an ActivityPub instance, PQ HTTP Signatures, DM-to-Mastodon-DM bridging. All explicitly out of M4 per the M4 brainstorm/impl-plan; unchanged here.
- Cross-session "don't ask again" for the public-post confirmation (session-scoped only).

---

## Open questions for spec review

1. **M4 inbound shape confirmation.** Confirm `PublicPostDelivery { verified_actor_url, activity_json }` is the final inbound contract and that `subscribe_to_public_posts()` emits end-to-end today (vs. the "until Stage 5.3" drop in `relay_transport.rs`). The read pane (Phase 3) depends on it. (Bob.)
2. **feed-renderer vs Rendition-variant.** This spec routes fediverse posts through a dedicated `feedPost.ts` renderer rather than a `Rendition::PublicPost` reader variant, because the post arrives via the broadcast channel, not an address fetch. Confirm this refinement of the brainstorm assumption.
3. **Reaction/typing wire ownership.** Confirm reactions (sealed message ref) and typing (presence-adjacent, setting-gated) are Bob's wire lane and that the UI-contract interfaces in 2.2/2.7 are the agreed seam.
4. **Markdown subset extent.** Confirm the allowed markdown subset (bold/italic/code/fenced-code/links/blockquote/lists) is right for v1.0, or trim/extend.
5. **Plan decomposition.** Confirm one implementation plan per workstream (three plans) vs. a single combined plan.

---

## Cross-references

- `docs/BRAND.md` - token + type contract, lockstep with etch>it.
- `docs/superpowers/plans/2026-06-07-m4-fediverse-brainstorm.md` and `-impl-plan.md` - the M4 bridge backend design (Bob's lane); this spec is the desktop UI half.
- `docs/superpowers/specs/2026-05-28-pq-content-and-groups-design.md` - sealed-envelope (M2) discipline the new message-borne content inherits.
- `docs/SECURITY.md` - the rendering/sanitization boundary the markdown + feedPost renderers must honor.
- Memory: `project-chat-ui-excellence` (locked design), `feedback-pq-claims` (honesty copy), `feedback-modular-desktop`, `feedback-brand-form`, `feedback-idiot-proof-ui`, `feedback-desktop-media-lazy`.
