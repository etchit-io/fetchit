# Profile Page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Render a contact's (or your own, or any looked-up handle's) Autonomi-published profile as a first-class read-only page in the fetch>it reader, addressable by `@handle@domain`, with a verified-identity badge, etchings gallery, share QR, and an etch/it creation handoff for fetch-only users.

**Architecture:** Shell-route (no core `Rendition` variant). The controller's submit path gains a second address class; profile tabs carry a canonical `profile:<agent_id>` address (so history/dedupe/bookmarks work) and a display string. A pure resolver (`resolveProfile`) composes the two shipped commands (`fediverse_lookup` for identity + continuity, `chat_fetch_profile` for the rich manifest) into one `ProfilePageModel`; a dispatch-shaped renderer (`renderProfilePage`) turns the model into DOM. The existing chat modal is demoted to a quick peek with an "Open full profile" link. No new network surface in the renderer; `htmlRewriter` and the iframe sandbox are untouched.

**Tech Stack:** vanilla TS + Vite + vitest/jsdom (frontend), Rust + Tauri 2 (`src-tauri`, workspace-excluded), the shipped `fetchit_chat::{profile,pair}` engine. Brand: oxidation tokens from `docs/BRAND.md` (`--font-display`, `--gold`, `--copper`, `--ash`, `--line`, `--r-card`); no colour literals.

**Branch:** `chat`. **DCO:** every commit `git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s`. No em-dashes in committed text. **Spec:** `docs/superpowers/specs/2026-06-12-profile-page-design.md` (d7f4559).

**Gates per task:** frontend `(cd apps/fetchit-desktop && npx tsc --noEmit && npm run test:run -- <name>)`; backend `(cd apps/fetchit-desktop/src-tauri && cargo test <name>)` then `cargo clippy --all-targets -- -D warnings`.

---

## File structure

| File | Create/Modify | Responsibility |
| --- | --- | --- |
| `apps/fetchit-desktop/src/address.ts` | Modify | Add `AddressInput` union + `parseAddressInput` (hex / `@handle@domain` / `profile:<id>`). |
| `apps/fetchit-desktop/src/address.test.ts` | Modify | Cover the three classes + garbage. |
| `apps/fetchit-desktop/src-tauri/src/profile.rs` | Modify | `chat_fetch_profile` gains `relay: Option<String>` via a pure `resolve_relay`. |
| `apps/fetchit-desktop/src/chat/api.ts` | Modify | `fetchProfile(agentId, relay?)` passes the hint. |
| `apps/fetchit-desktop/src/profile/open.ts` | Create | `ProfilePageModel`, `resolveProfile`, `relayFromShareUri`. |
| `apps/fetchit-desktop/src/profile/open.test.ts` | Create | Resolver branches with injected deps. |
| `apps/fetchit-desktop/src/profile/page.ts` | Create | `renderProfilePage` (banner + states + gallery + actions). |
| `apps/fetchit-desktop/src/profile/page.test.ts` | Create | One render test per state + actions matrix + gallery. |
| `apps/fetchit-desktop/src-tauri/src/etchit_handoff.rs` | Create | `etchit_handoff` probe + `etchit_open_profile` launch. |
| `apps/fetchit-desktop/src-tauri/src/lib.rs` | Modify | Register the two etch/it commands. |
| `apps/fetchit-desktop/src/profile/handoff.ts` | Create | Typed wrappers for the two commands. |
| `apps/fetchit-desktop/src/tabs.ts` | Modify | `display` field + `renderProfile` mark. |
| `apps/fetchit-desktop/src/ui/addressBar.ts` | Modify | `onProfile` hook for non-hex classes. |
| `apps/fetchit-desktop/src/controller.ts` | Modify | `startProfile` flow + openProfile wiring + manifest-banner handler. |
| `apps/fetchit-desktop/src/fediverse/lookup.ts` | Modify | "View profile" action -> `onViewProfile`. |
| `apps/fetchit-desktop/src/chat/profileCard.ts` | Modify | "Open full profile" button. |
| `apps/fetchit-desktop/src/renderers/json.ts` | Modify | Profile-manifest detection banner. |
| `apps/fetchit-desktop/src/renderers/dispatch.ts` | Modify | Thread `onViewProfile` to `renderJson`. |
| `apps/fetchit-desktop/src/styles.css` | Modify | `.profile-page` block (tokens only). |

---

## Task 1: Address-class parser

**Files:**
- Modify: `apps/fetchit-desktop/src/address.ts`
- Modify: `apps/fetchit-desktop/src/address.test.ts`

- [ ] **Step 1: Write the failing tests** (append to `address.test.ts`)

```ts
import { parseAddressInput } from "./address";

describe("parseAddressInput", () => {
  it("classifies a 64-hex address as hex", () => {
    const r = parseAddressInput("a".repeat(64));
    expect(r).toEqual({ kind: "hex", address: "a".repeat(64), query: "" });
  });
  it("classifies @name@domain as a lowercased handle", () => {
    expect(parseAddressInput("  @Josh@etchit.io ")).toEqual({
      kind: "handle",
      handle: "@josh@etchit.io",
    });
  });
  it("classifies profile:<64hex> as a profile agent id", () => {
    expect(parseAddressInput(`profile:${"b".repeat(64)}`)).toEqual({
      kind: "profile",
      agentId: "b".repeat(64),
    });
  });
  it("returns null for garbage", () => {
    expect(parseAddressInput("not an address")).toBeNull();
    expect(parseAddressInput("@no-domain")).toBeNull();
    expect(parseAddressInput("profile:short")).toBeNull();
  });
});
```

- [ ] **Step 2: Run to verify fail**

Run: `(cd apps/fetchit-desktop && npm run test:run -- address)`
Expected: FAIL, `parseAddressInput` is not exported.

- [ ] **Step 3: Implement** (append to `address.ts`)

```ts
/** A pasted/typed address resolved to one of the reader's input classes. */
export type AddressInput =
  | { kind: "hex"; address: string; query: string }
  | { kind: "handle"; handle: string }
  | { kind: "profile"; agentId: string };

const HANDLE_INPUT = /^@[^@\s]+@[^@\s]+\.[^@\s]+$/;
const PROFILE_INPUT = /^profile:([0-9a-fA-F]{64})$/;

/**
 * Classify an address-bar input. Bare 64-hex is always an Autonomi
 * content address (hex); an agent-id profile uses the explicit
 * `profile:` prefix, so the two never collide. Handles are lowercased
 * (the registry is lowercase-canonical).
 */
export function parseAddressInput(raw: string): AddressInput | null {
  const t = raw.trim();
  const prof = PROFILE_INPUT.exec(t);
  if (prof) return { kind: "profile", agentId: prof[1].toLowerCase() };
  const lower = t.toLowerCase();
  if (HANDLE_INPUT.test(lower)) return { kind: "handle", handle: lower };
  const hex = parseAutonomiUrl(t);
  if (hex) return { kind: "hex", address: hex.address, query: hex.query };
  return null;
}
```

- [ ] **Step 4: Run to verify pass**

Run: `(cd apps/fetchit-desktop && npx tsc --noEmit && npm run test:run -- address)`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/fetchit-desktop/src/address.ts apps/fetchit-desktop/src/address.test.ts
git commit -s -m "feat(desktop): address-class parser for handle and profile inputs"
```

---

## Task 2: Backend relay hint on `chat_fetch_profile`

**Files:**
- Modify: `apps/fetchit-desktop/src-tauri/src/profile.rs`
- Modify: `apps/fetchit-desktop/src/chat/api.ts`

- [ ] **Step 1: Write the failing test** (add to the `tests` module in `profile.rs`)

```rust
#[test]
fn resolve_relay_prefers_valid_hint_else_configured() {
    let configured = url::Url::parse("https://relay.configured/").unwrap();
    // No hint -> configured.
    assert_eq!(resolve_relay(&configured, None).unwrap(), configured);
    // Valid hint -> the hint.
    let got = resolve_relay(&configured, Some("https://relay.hint:8088/")).unwrap();
    assert_eq!(got.as_str(), "https://relay.hint:8088/");
    // Garbage hint -> error, never silently falls back.
    assert!(resolve_relay(&configured, Some("not a url")).is_err());
}
```

- [ ] **Step 2: Run to verify fail**

Run: `(cd apps/fetchit-desktop/src-tauri && cargo test resolve_relay_prefers)`
Expected: FAIL, `resolve_relay` not defined.

- [ ] **Step 3: Implement** (add the pure fn above `chat_fetch_profile`, then thread it in)

```rust
/// Choose the relay to resolve a profile against: an explicit hint when
/// present (parsed + validated), otherwise the configured relay. A
/// malformed hint is an error, never a silent fallback.
fn resolve_relay(configured: &url::Url, hint: Option<&str>) -> Result<url::Url, String> {
    match hint {
        None => Ok(configured.clone()),
        Some(h) => url::Url::parse(h).map_err(|e| format!("bad relay hint: {e}")),
    }
}
```

Change the command signature and relay line:

```rust
pub async fn chat_fetch_profile(
    app_state: tauri::State<'_, crate::AppState>,
    state: tauri::State<'_, crate::chat::ChatState>,
    agent_id: String,
    relay: Option<String>,
) -> Result<ProfileOutcome, String> {
    crate::chat::ensure_chat_enabled(&app_state)?;
    fetchit_chat::identity::AgentId::parse(&agent_id).map_err(|e| e.to_string())?;
    let relay = resolve_relay(&state.relay_url(), relay.as_deref())?;
    // ...unchanged below: guarded_client(), fetch_index_record_by_id(&relay, ...)
```

(The SSRF host guard already runs inside `fetch_index_record_by_id`; the hint is validated as a URL here and guarded there.)

- [ ] **Step 4: Update the TS wrapper** (`chat/api.ts`)

```ts
export async function fetchProfile(
  agentId: string,
  relay?: string | null,
): Promise<ProfileOutcome> {
  return invoke<ProfileOutcome>("chat_fetch_profile", { agentId, relay: relay ?? null });
}
```

- [ ] **Step 5: Run + commit**

Run: `(cd apps/fetchit-desktop/src-tauri && cargo test resolve_relay && cargo clippy --all-targets -- -D warnings)` then `(cd apps/fetchit-desktop && npx tsc --noEmit)`
Expected: PASS / clean.

```bash
git add apps/fetchit-desktop/src-tauri/src/profile.rs apps/fetchit-desktop/src/chat/api.ts
git commit -s -m "feat(desktop): optional relay hint on chat_fetch_profile"
```

---

## Task 3: Profile resolver (`open.ts`)

**Files:**
- Create: `apps/fetchit-desktop/src/profile/open.ts`
- Create: `apps/fetchit-desktop/src/profile/open.test.ts`

- [ ] **Step 1: Write the failing tests**

```ts
import { resolveProfile, relayFromShareUri, type ProfilePageModel } from "./open";

const VERIFIED = {
  kind: "verified" as const,
  handle: "@josh@etchit.io",
  actorUrl: "https://etchit.io/actors/josh",
  agentIdHex: "a".repeat(64),
  displayName: "Josh",
  bio: "hi",
  avatar: null,
  shareUri: `fetchit://share/v3/${"a".repeat(64)}/${"c".repeat(64)}?relay=https://r.example/`,
  previousAgentIdHex: null,
  verifyFailure: null,
};
const PROFILE_OUTCOME = {
  kind: "profile" as const,
  displayName: "Josh",
  bio: "hi",
  website: "https://tankcheck.net",
  links: [{ kind: "etchit", label: "showcase", addr: "d".repeat(64) }],
  avatar: null,
  issuedAtMs: 1,
};

it("extracts the relay from a v3 share uri", () => {
  expect(relayFromShareUri(VERIFIED.shareUri)).toBe("https://r.example/");
  expect(relayFromShareUri("garbage")).toBeNull();
});

it("merges lookup identity with manifest links for a verified handle", async () => {
  const m = await resolveProfile(
    { kind: "handle", handle: "@josh@etchit.io" },
    { lookupHandle: async () => VERIFIED, fetchProfile: async () => PROFILE_OUTCOME },
  );
  expect(m.state).toBe("verified");
  expect(m.verified).toBe(true);
  expect(m.handle).toBe("@josh@etchit.io");
  expect(m.website).toBe("https://tankcheck.net");
  expect(m.links).toHaveLength(1);
  expect(m.shareUri).toBe(VERIFIED.shareUri);
});

it("renders public-only with a visible failure and no private fields", async () => {
  const m = await resolveProfile(
    { kind: "handle", handle: "@x@y.io" },
    {
      lookupHandle: async () => ({ ...VERIFIED, kind: "publicOnly", agentIdHex: null, shareUri: null, verifyFailure: "bad sig" }),
      fetchProfile: async () => { throw new Error("must not be called"); },
    },
  );
  expect(m.state).toBe("publicOnly");
  expect(m.verified).toBe(false);
  expect(m.verifyFailure).toBe("bad sig");
  expect(m.shareUri).toBeNull();
});

it("flags changed-hands from the continuity ledger", async () => {
  const m = await resolveProfile(
    { kind: "handle", handle: "@josh@etchit.io" },
    { lookupHandle: async () => ({ ...VERIFIED, previousAgentIdHex: "f".repeat(64) }), fetchProfile: async () => PROFILE_OUTCOME },
  );
  expect(m.changedHands).toBe(true);
});

it("resolves an agent-id contact via chat_fetch_profile alone", async () => {
  const m = await resolveProfile(
    { kind: "agentId", agentId: "a".repeat(64), isSelf: true },
    { lookupHandle: async () => { throw new Error("must not be called"); }, fetchProfile: async () => PROFILE_OUTCOME },
  );
  expect(m.state).toBe("verified");
  expect(m.isSelf).toBe(true);
  expect(m.handle).toBeNull();
  expect(m.links).toHaveLength(1);
});

it("returns none when an agent-id contact has not published", async () => {
  const m = await resolveProfile(
    { kind: "agentId", agentId: "a".repeat(64), isSelf: true },
    { lookupHandle: async () => { throw new Error("nope"); }, fetchProfile: async () => ({ kind: "none" }) },
  );
  expect(m.state).toBe("none");
});
```

- [ ] **Step 2: Run to verify fail**

Run: `(cd apps/fetchit-desktop && npm run test:run -- open)`
Expected: FAIL, module not found.

- [ ] **Step 3: Implement** (`open.ts`)

```ts
import type { LookupResult } from "../fediverse/api";
import type { ProfileOutcome, ProfileLinkDto, ProfileAvatarMeta } from "../chat/types";

export interface ProfilePageModel {
  state: "verified" | "publicOnly" | "none" | "error";
  agentId: string | null;
  handle: string | null;
  display: string;
  verified: boolean;
  changedHands: boolean;
  verifyFailure: string | null;
  bio: string | null;
  website: string | null;
  avatar: ProfileAvatarMeta | null;
  links: ProfileLinkDto[];
  shareUri: string | null;
  isSelf: boolean;
  error: string | null;
}

export type ProfileInput =
  | { kind: "handle"; handle: string; relayHint?: string | null; isSelf?: boolean }
  | { kind: "agentId"; agentId: string; relayHint?: string | null; isSelf?: boolean; display?: string };

export interface ResolveDeps {
  lookupHandle: (handle: string) => Promise<LookupResult>;
  fetchProfile: (agentId: string, relay?: string | null) => Promise<ProfileOutcome>;
}

/** Pull the `?relay=` value out of a v3 share URI. `fetchit://` does not
 * parse as a WHATWG URL, so read the query by hand. */
export function relayFromShareUri(uri: string): string | null {
  const q = uri.indexOf("?");
  if (q < 0) return null;
  const params = new URLSearchParams(uri.slice(q + 1));
  return params.get("relay");
}

function empty(over: Partial<ProfilePageModel>): ProfilePageModel {
  return {
    state: "error", agentId: null, handle: null, display: "", verified: false,
    changedHands: false, verifyFailure: null, bio: null, website: null,
    avatar: null, links: [], shareUri: null, isSelf: false, error: null, ...over,
  };
}

export async function resolveProfile(input: ProfileInput, deps: ResolveDeps): Promise<ProfilePageModel> {
  if (input.kind === "handle") return resolveHandle(input, deps);
  return resolveAgentId(input, deps);
}

async function resolveHandle(
  input: Extract<ProfileInput, { kind: "handle" }>,
  deps: ResolveDeps,
): Promise<ProfilePageModel> {
  let look: LookupResult;
  try {
    look = await deps.lookupHandle(input.handle);
  } catch (e) {
    return empty({ handle: input.handle, display: input.handle, error: errText(e) });
  }
  const base = empty({
    handle: look.handle,
    display: look.displayName || look.handle,
    agentId: look.agentIdHex ?? null,
    bio: look.bio ?? null,
    avatar: look.avatar ?? null,
    shareUri: look.shareUri ?? null,
    verifyFailure: look.verifyFailure ?? null,
    changedHands: !!look.previousAgentIdHex,
    isSelf: !!input.isSelf,
  });
  if (look.kind !== "verified" || !look.agentIdHex) {
    return { ...base, state: "publicOnly", verified: false };
  }
  // Verified: enrich with the manifest (links/website). A manifest miss
  // degrades to identity-only, never an error (the binding already proved).
  const relay = input.relayHint ?? (look.shareUri ? relayFromShareUri(look.shareUri) : null);
  try {
    const out = await deps.fetchProfile(look.agentIdHex, relay);
    if (out.kind === "profile") {
      return { ...base, state: "verified", verified: true, website: out.website ?? null, links: out.links, bio: out.bio ?? base.bio, avatar: out.avatar ?? base.avatar };
    }
  } catch {
    /* identity-only */
  }
  return { ...base, state: "verified", verified: true };
}

async function resolveAgentId(
  input: Extract<ProfileInput, { kind: "agentId" }>,
  deps: ResolveDeps,
): Promise<ProfilePageModel> {
  let out: ProfileOutcome;
  try {
    out = await deps.fetchProfile(input.agentId, input.relayHint ?? null);
  } catch (e) {
    return empty({ agentId: input.agentId, display: input.display || short(input.agentId), isSelf: !!input.isSelf, error: errText(e) });
  }
  if (out.kind === "none") {
    return empty({ state: "none", agentId: input.agentId, display: input.display || short(input.agentId), isSelf: !!input.isSelf });
  }
  return empty({
    state: "verified", verified: true, agentId: input.agentId,
    display: out.displayName || input.display || short(input.agentId),
    bio: out.bio ?? null, website: out.website ?? null, links: out.links,
    avatar: out.avatar ?? null, isSelf: !!input.isSelf,
  });
}

function short(id: string): string {
  return `${id.slice(0, 6)}…${id.slice(-4)}`;
}
function errText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
```

- [ ] **Step 4: Run to verify pass**

Run: `(cd apps/fetchit-desktop && npx tsc --noEmit && npm run test:run -- open)`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add apps/fetchit-desktop/src/profile/open.ts apps/fetchit-desktop/src/profile/open.test.ts
git commit -s -m "feat(desktop): profile resolver merging lookup identity + manifest"
```

---

## Task 4: Profile page renderer, identity band + states

**Files:**
- Create: `apps/fetchit-desktop/src/profile/page.ts`
- Create: `apps/fetchit-desktop/src/profile/page.test.ts`
- Modify: `apps/fetchit-desktop/src/styles.css`

- [ ] **Step 1: Write the failing tests**

```ts
import { renderProfilePage, type ProfilePageHandlers } from "./page";
import type { ProfilePageModel } from "./open";

const noop = () => {};
const H: ProfilePageHandlers = {
  onAutonomi: noop, onMessage: noop, onInvite: noop, onShare: noop,
  onEditEtch: noop, onGetEtch: noop, confirmOpen: noop,
};
const stubAvatar = async () => "data:image/webp;base64,AA==";
function model(over: Partial<ProfilePageModel>): ProfilePageModel {
  return { state: "verified", agentId: "a".repeat(64), handle: "@josh@etchit.io",
    display: "Josh", verified: true, changedHands: false, verifyFailure: null,
    bio: "hi", website: null, avatar: null, links: [], shareUri: "fetchit://share/v3/x", isSelf: false, error: null, ...over };
}

it("verified page shows the badge, name, and private actions", () => {
  const root = document.createElement("div");
  renderProfilePage(model({}), root, H, stubAvatar);
  expect(root.querySelector(".profile-page__badge")).not.toBeNull();
  expect(root.querySelector(".profile-page__name")?.textContent).toBe("Josh");
  expect(root.querySelector("[data-act=message]")).not.toBeNull();
  expect(root.querySelector("[data-act=invite]")).not.toBeNull();
});

it("public-only page hides private actions and shows the failure", () => {
  const root = document.createElement("div");
  renderProfilePage(model({ state: "publicOnly", verified: false, verifyFailure: "bad sig" }), root, H, stubAvatar);
  expect(root.querySelector(".profile-page__badge")).toBeNull();
  expect(root.querySelector("[data-act=message]")).toBeNull();
  expect(root.querySelector(".profile-page__verify-fail")?.textContent).toContain("bad sig");
});

it("changed-hands renders the warning band", () => {
  const root = document.createElement("div");
  renderProfilePage(model({ changedHands: true }), root, H, stubAvatar);
  expect(root.querySelector(".profile-page__changed")).not.toBeNull();
});

it("error state renders an honest card, no trust affordances", () => {
  const root = document.createElement("div");
  renderProfilePage(model({ state: "error", error: "network down", verified: false }), root, H, stubAvatar);
  expect(root.querySelector(".profile-page__error")?.textContent).toContain("network down");
  expect(root.querySelector("[data-act=message]")).toBeNull();
});

it("escapes untrusted display fields (textContent, never innerHTML)", () => {
  const root = document.createElement("div");
  renderProfilePage(model({ display: "<img src=x onerror=alert(1)>" }), root, H, stubAvatar);
  expect(root.querySelector("img")).toBeNull();
});
```

- [ ] **Step 2: Run to verify fail**

Run: `(cd apps/fetchit-desktop && npm run test:run -- page)`
Expected: FAIL, module not found.

- [ ] **Step 3: Implement** (`page.ts`)

```ts
import type { ProfilePageModel } from "./open";
import { avatarGradientClass } from "../chat/avatarColor";

export interface ProfilePageHandlers {
  onAutonomi: (uri: string) => void;
  onMessage: (m: ProfilePageModel) => void;
  onInvite: (m: ProfilePageModel) => void;
  onShare: (m: ProfilePageModel) => void;
  onEditEtch: () => void;
  onGetEtch: () => void;
  confirmOpen: (url: string) => void;
}

type Avatar = (addr: string, mime: string, bytesLen: number) => Promise<string>;

function line(cls: string, text: string): HTMLElement {
  const el = document.createElement("div");
  el.className = cls;
  el.textContent = text;
  return el;
}
function btn(act: string, cls: string, text: string, on: () => void): HTMLButtonElement {
  const b = document.createElement("button");
  b.type = "button";
  b.className = cls;
  b.dataset.act = act;
  b.textContent = text;
  b.addEventListener("click", on);
  return b;
}

export function renderProfilePage(
  model: ProfilePageModel,
  root: HTMLElement,
  h: ProfilePageHandlers,
  fetchAvatar: Avatar,
): void {
  root.replaceChildren();
  root.classList.add("profile-page");

  if (model.state === "error") {
    root.appendChild(line("profile-page__error", model.error ?? "this profile could not be loaded"));
    return;
  }

  const band = document.createElement("header");
  band.className = "profile-page__band";

  const avatar = document.createElement("div");
  avatar.className = "profile-page__avatar";
  if (model.agentId) avatar.classList.add(avatarGradientClass(model.agentId));
  band.appendChild(avatar);
  if (model.avatar) {
    const a = model.avatar;
    void fetchAvatar(a.addr, a.mime, a.bytesLen)
      .then((url) => {
        const img = document.createElement("img");
        img.alt = "avatar";
        img.draggable = false;
        img.src = url;
        avatar.replaceChildren(img);
      })
      .catch(() => {});
  }

  const idCol = document.createElement("div");
  idCol.className = "profile-page__id";
  const nameRow = document.createElement("div");
  nameRow.className = "profile-page__namerow";
  nameRow.appendChild(line("profile-page__name", model.display));
  if (model.verified) nameRow.appendChild(line("profile-page__badge", "verified identity"));
  idCol.appendChild(nameRow);
  if (model.handle) idCol.appendChild(line("profile-page__handle", model.handle));
  band.appendChild(idCol);

  band.appendChild(buildActions(model, h));
  root.appendChild(band);

  if (model.changedHands) {
    root.appendChild(line("profile-page__changed",
      "This handle previously pointed to different keys. Treat this as a new person."));
  }
  if (model.state === "publicOnly" && model.verifyFailure) {
    root.appendChild(line("profile-page__verify-fail",
      `Identity could not be verified (${model.verifyFailure}). Private messaging is off.`));
  }
  if (model.bio) root.appendChild(line("profile-page__bio", model.bio));
  if (model.website) {
    const w = btn("website", "profile-page__website", model.website, () => h.confirmOpen(model.website as string));
    root.appendChild(w);
  }
}

function buildActions(model: ProfilePageModel, h: ProfilePageHandlers): HTMLElement {
  const row = document.createElement("div");
  row.className = "profile-page__actions";
  if (model.isSelf) {
    row.appendChild(btn("edit-etch", "profile-page__act", "Edit in etch/it", h.onEditEtch));
  } else if (model.verified && model.agentId) {
    row.appendChild(btn("message", "profile-page__act profile-page__act--primary", "Message", () => h.onMessage(model)));
    row.appendChild(btn("invite", "profile-page__act", "Invite to group", () => h.onInvite(model)));
  }
  if (model.agentId) {
    row.appendChild(btn("share", "profile-page__act", "Share", () => h.onShare(model)));
  }
  return row;
}
```

- [ ] **Step 4: Add the CSS** (append to `styles.css`, tokens only)

```css
.profile-page { max-width: 720px; margin: 0 auto; padding: 24px; }
.profile-page__band { display: flex; align-items: center; gap: 16px;
  background: var(--bone-dim); border: 1px solid var(--line);
  border-radius: var(--r-card); padding: 16px; box-shadow: var(--edge-highlight); }
.profile-page__avatar { width: 64px; height: 64px; border-radius: var(--r-pill);
  border: 2px solid var(--gold); overflow: hidden; flex: none; }
.profile-page__avatar img { width: 100%; height: 100%; object-fit: cover; }
.profile-page__id { flex: 1; min-width: 0; }
.profile-page__namerow { display: flex; align-items: baseline; gap: 10px; }
.profile-page__name { font-family: var(--font-display); font-size: 22px; color: var(--ink); }
.profile-page__badge { color: var(--gold); font-size: 12px; font-weight: 600; }
.profile-page__handle { color: var(--copper); font-size: 13px; }
.profile-page__actions { display: flex; gap: 8px; }
.profile-page__act { border: 1px solid var(--line); border-radius: var(--r-pill);
  padding: 6px 14px; background: transparent; color: var(--ink); cursor: pointer; }
.profile-page__act--primary { background: var(--copper); color: var(--bone); border-color: transparent; }
.profile-page__changed, .profile-page__verify-fail { margin-top: 12px; font-size: 13px;
  border-left: 3px solid var(--rust); padding-left: 10px; color: var(--ash); }
.profile-page__bio { margin-top: 14px; color: var(--ink-2); }
.profile-page__website { margin-top: 8px; background: transparent; border: none;
  color: var(--copper); cursor: pointer; padding: 0; }
.profile-page__error { padding: 40px; text-align: center; color: var(--ash); }
```

- [ ] **Step 5: Run + commit**

Run: `(cd apps/fetchit-desktop && npx tsc --noEmit && npm run test:run -- page)`
Expected: PASS (5 tests).

```bash
git add apps/fetchit-desktop/src/profile/page.ts apps/fetchit-desktop/src/profile/page.test.ts apps/fetchit-desktop/src/styles.css
git commit -s -m "feat(desktop): profile page renderer with identity band + states"
```

---

## Task 5: Etchings gallery + lazy avatar assertion

**Files:**
- Modify: `apps/fetchit-desktop/src/profile/page.ts`
- Modify: `apps/fetchit-desktop/src/profile/page.test.ts`
- Modify: `apps/fetchit-desktop/src/styles.css`

- [ ] **Step 1: Write the failing tests** (append to `page.test.ts`)

```ts
const GALLERY = [
  { kind: "etchit", label: "showcase", addr: "d".repeat(64) },
  { kind: "fetchit", label: "city", addr: "e".repeat(64) },
  { kind: "website", label: "site", addr: "https://x.io" },
];

it("renders hex-kind links as gallery cards and opens them in the reader", () => {
  const opened: string[] = [];
  const root = document.createElement("div");
  renderProfilePage(model({ links: GALLERY }), root, { ...H, onAutonomi: (u) => opened.push(u) }, stubAvatar);
  const cards = root.querySelectorAll(".profile-page__etch");
  expect(cards).toHaveLength(2); // website excluded from the grid
  (cards[0] as HTMLElement).click();
  expect(opened[0]).toBe(`autonomi://${"d".repeat(64)}`);
});

it("website + unknown link kinds render as chips, not gallery cards", () => {
  const root = document.createElement("div");
  renderProfilePage(model({ links: GALLERY }), root, H, stubAvatar);
  expect(root.querySelectorAll(".profile-page__chip")).toHaveLength(1);
});

it("gallery fires zero fetches on render", () => {
  let calls = 0;
  const root = document.createElement("div");
  renderProfilePage(model({ links: GALLERY }), root, H, async () => { calls++; return ""; });
  expect(calls).toBe(0); // no avatar in this model, no link prefetch
});
```

- [ ] **Step 2: Run to verify fail**

Run: `(cd apps/fetchit-desktop && npm run test:run -- page)`
Expected: FAIL, no `.profile-page__etch` elements.

- [ ] **Step 3: Implement** (append to `renderProfilePage`, after the website block)

```ts
  const HEX_KINDS = new Set(["etchit", "fetchit", "image"]);
  const gallery = model.links.filter((l) => HEX_KINDS.has(l.kind));
  const chips = model.links.filter((l) => !HEX_KINDS.has(l.kind));

  if (gallery.length > 0) {
    root.appendChild(line("profile-page__label", "Etchings"));
    const grid = document.createElement("div");
    grid.className = "profile-page__gallery";
    for (const l of gallery) {
      const card = document.createElement("button");
      card.type = "button";
      card.className = "profile-page__etch";
      card.dataset.kind = l.kind;
      card.append(line("profile-page__etch-kind", l.kind), line("profile-page__etch-label", l.label || l.kind));
      card.addEventListener("click", () => h.onAutonomi(`autonomi://${l.addr}`));
      grid.appendChild(card);
    }
    root.appendChild(grid);
  }
  if (chips.length > 0) {
    const row = document.createElement("div");
    row.className = "profile-page__chips";
    for (const l of chips) {
      const chip = document.createElement("button");
      chip.type = "button";
      chip.className = "profile-page__chip";
      chip.textContent = l.label || l.kind;
      chip.addEventListener("click", () => {
        if (l.kind === "website") h.confirmOpen(l.addr);
      });
      row.appendChild(chip);
    }
    root.appendChild(row);
  }
```

- [ ] **Step 4: Add CSS** (append to `styles.css`)

```css
.profile-page__label { margin: 20px 0 8px; font-size: 11px; letter-spacing: .12em;
  text-transform: uppercase; color: var(--ash); }
.profile-page__gallery { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; }
.profile-page__etch { text-align: left; border: 1px solid var(--line);
  border-radius: var(--r-card); padding: 10px; background: var(--bone-dim); cursor: pointer; }
.profile-page__etch-kind { font-size: 10px; letter-spacing: .06em; color: var(--gold); }
.profile-page__etch-label { color: var(--ink); }
.profile-page__chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 12px; }
.profile-page__chip { border: 1px solid var(--line); border-radius: var(--r-pill);
  padding: 4px 12px; background: transparent; color: var(--copper); cursor: pointer; }
```

- [ ] **Step 5: Run + commit**

Run: `(cd apps/fetchit-desktop && npx tsc --noEmit && npm run test:run -- page)`
Expected: PASS.

```bash
git add apps/fetchit-desktop/src/profile/page.ts apps/fetchit-desktop/src/profile/page.test.ts apps/fetchit-desktop/src/styles.css
git commit -s -m "feat(desktop): profile etchings gallery + link chips"
```

---

## Task 6: Own-profile Trinity empty state

**Files:**
- Modify: `apps/fetchit-desktop/src/profile/page.ts`
- Modify: `apps/fetchit-desktop/src/profile/page.test.ts`
- Modify: `apps/fetchit-desktop/src/styles.css`

- [ ] **Step 1: Write the failing tests** (append)

```ts
it("own empty page shows the trinity handoff, both actions", () => {
  let edit = 0, get = 0;
  const root = document.createElement("div");
  renderProfilePage(model({ state: "none", verified: false, isSelf: true }), root,
    { ...H, onEditEtch: () => edit++, onGetEtch: () => get++ }, stubAvatar);
  expect(root.querySelector(".profile-page__handoff")).not.toBeNull();
  (root.querySelector("[data-act=create-etch]") as HTMLElement).click();
  (root.querySelector("[data-act=get-etch]") as HTMLElement).click();
  expect(edit).toBe(1);
  expect(get).toBe(1);
});

it("contact empty page is neutral, no etch/it advertising", () => {
  const root = document.createElement("div");
  renderProfilePage(model({ state: "none", verified: false, isSelf: false }), root, H, stubAvatar);
  expect(root.querySelector(".profile-page__handoff")).toBeNull();
  expect(root.querySelector(".profile-page__empty")?.textContent).toContain("hasn't published");
});
```

- [ ] **Step 2: Run to verify fail**

Run: `(cd apps/fetchit-desktop && npm run test:run -- page)`
Expected: FAIL.

- [ ] **Step 3: Implement** (at the TOP of `renderProfilePage`, right after the `error` block)

```ts
  if (model.state === "none") {
    root.appendChild(model.isSelf ? buildHandoff(h) : line("profile-page__empty", "This contact hasn't published a profile yet."));
    return;
  }
```

Add the builder:

```ts
function buildHandoff(h: ProfilePageHandlers): HTMLElement {
  const card = document.createElement("div");
  card.className = "profile-page__handoff";
  card.append(
    line("profile-page__handoff-title", "Make this page yours"),
    line("profile-page__handoff-chain", "etch/ writes  ->  Autonomi keeps  ->  fetch> shows"),
    line("profile-page__handoff-body",
      "Your profile lives on Autonomi: permanent, post-quantum, yours. People who look you up land here."),
  );
  const row = document.createElement("div");
  row.className = "profile-page__actions";
  row.append(
    btn("create-etch", "profile-page__act profile-page__act--primary", "Create my profile in etch/it", h.onEditEtch),
    btn("get-etch", "profile-page__act", "Get etch/it", h.onGetEtch),
  );
  card.appendChild(row);
  return card;
}
```

- [ ] **Step 4: Add CSS** (append)

```css
.profile-page__handoff, .profile-page__empty { text-align: center; padding: 40px 24px;
  border: 1px solid var(--line); border-radius: var(--r-card); background: var(--bone-dim); }
.profile-page__empty { color: var(--ash); }
.profile-page__handoff-title { font-family: var(--font-display); font-size: 20px; color: var(--ink); }
.profile-page__handoff-chain { color: var(--gold); margin: 8px 0; }
.profile-page__handoff-body { color: var(--ink-2); max-width: 420px; margin: 0 auto 16px; }
.profile-page__handoff .profile-page__actions { justify-content: center; }
```

- [ ] **Step 5: Run + commit**

Run: `(cd apps/fetchit-desktop && npx tsc --noEmit && npm run test:run -- page)`
Expected: PASS.

```bash
git add apps/fetchit-desktop/src/profile/page.ts apps/fetchit-desktop/src/profile/page.test.ts apps/fetchit-desktop/src/styles.css
git commit -s -m "feat(desktop): own-profile trinity handoff empty state"
```

---

## Task 7: etch/it handoff backend command

**Files:**
- Create: `apps/fetchit-desktop/src-tauri/src/etchit_handoff.rs`
- Modify: `apps/fetchit-desktop/src-tauri/src/lib.rs`
- Create: `apps/fetchit-desktop/src/profile/handoff.ts`

- [ ] **Step 1: Write the failing test** (in `etchit_handoff.rs`)

```rust
//! etch/it creation handoff. fetch>it never writes; it points the user
//! at etch>it (the publisher) to create or edit their Autonomi profile.

/// True if any known etch/it binary name resolves via the injected
/// path lookup. Pure so the probe is testable without a real PATH.
fn etchit_installed(on_path: impl Fn(&str) -> bool) -> bool {
    ["etchit", "etch-it", "etchit-desktop"].iter().any(|n| on_path(n))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    #[test]
    fn detects_installed_by_any_known_name() {
        assert!(etchit_installed(|n| n == "etch-it"));
        assert!(!etchit_installed(|_| false));
    }
}
```

- [ ] **Step 2: Run to verify fail**

Run: `(cd apps/fetchit-desktop/src-tauri && cargo test detects_installed_by_any_known_name)`
Expected: FAIL, module not declared.

- [ ] **Step 3: Implement** (rest of `etchit_handoff.rs`)

```rust
use serde::Serialize;

/// Result of probing for an installed etch/it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HandoffProbe {
    /// Whether an etch/it binary was found on PATH.
    pub installed: bool,
}

fn on_path(name: &str) -> bool {
    let Ok(path) = std::env::var("PATH") else { return false };
    std::env::split_paths(&path).any(|dir| {
        let p = dir.join(name);
        p.is_file() || p.with_extension("exe").is_file()
    })
}

/// Probe for an installed etch/it (PATH lookup). Non-fatal: the UI
/// always offers a "Get etch/it" fallback regardless of the result.
#[tauri::command]
#[must_use]
pub fn etchit_handoff() -> HandoffProbe {
    HandoffProbe { installed: etchit_installed(on_path) }
}

/// Open etch/it's profile editor via its registered URI scheme. Fixed
/// target, no user input near the opener.
///
/// # Errors
/// Returns a user-facing string if the OS opener fails.
#[tauri::command]
pub fn etchit_open_profile(app: tauri::AppHandle) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .open_url("etchit://profile", None::<&str>)
        .map_err(|e| format!("couldn't open etch/it ({e})"))
}
```

Register in `lib.rs` (`mod etchit_handoff;` near the other `mod`s, and in `generate_handler!`):

```rust
            etchit_handoff::etchit_handoff,
            etchit_handoff::etchit_open_profile,
```

- [ ] **Step 4: TS wrappers** (`profile/handoff.ts`)

```ts
import { invoke } from "@tauri-apps/api/core";

export async function probeEtchit(): Promise<{ installed: boolean }> {
  return invoke<{ installed: boolean }>("etchit_handoff");
}
export async function openEtchitProfile(): Promise<void> {
  await invoke("etchit_open_profile");
}
```

- [ ] **Step 5: Run + commit**

Run: `(cd apps/fetchit-desktop/src-tauri && cargo test etchit && cargo clippy --all-targets -- -D warnings)`
Expected: PASS / clean. (Confirm `tauri-plugin-opener` is a dependency; it backs the existing external-open path. If the opener API path differs, match the version already used in `lib.rs`.)

```bash
git add apps/fetchit-desktop/src-tauri/src/etchit_handoff.rs apps/fetchit-desktop/src-tauri/src/lib.rs apps/fetchit-desktop/src/profile/handoff.ts
git commit -s -m "feat(desktop): etch/it profile-creation handoff command"
```

---

## Task 8: Controller integration (the front door)

**Files:**
- Modify: `apps/fetchit-desktop/src/tabs.ts`
- Modify: `apps/fetchit-desktop/src/ui/addressBar.ts`
- Modify: `apps/fetchit-desktop/src/controller.ts`

- [ ] **Step 1: Write the failing test** (`tabs.test.ts`, create if absent)

```ts
import { TabStore } from "./tabs";

it("renderProfile marks a tab rendered with a display label and no rendition", () => {
  const store = new TabStore();
  const tab = store.createEmpty(document.createElement("div"));
  store.startFetch(tab.id, `profile:${"a".repeat(64)}`);
  store.renderProfile(tab.id, "@josh@etchit.io");
  const t = store.active()!;
  expect(t.status).toBe("rendered");
  expect(t.rendition).toBeNull();
  expect(t.display).toBe("@josh@etchit.io");
  expect(t.shortLabel).toBe("@josh@etchit.io");
});
```

- [ ] **Step 2: Run to verify fail**

Run: `(cd apps/fetchit-desktop && npm run test:run -- tabs)`
Expected: FAIL, `renderProfile` not a function.

- [ ] **Step 3: Implement** — `tabs.ts`: add `display` to `Tab`, default `null` in `createEmpty`, and the mark method.

```ts
// in interface Tab:
  /** Friendly label shown in the address bar for non-hex tabs (e.g. a handle). */
  display: string | null;
// in createEmpty's tab literal: add `display: null,`
// new method:
  /** Mark a profile (shell-route) tab rendered: no Rendition, carry a display label. */
  renderProfile(id: string, display: string): void {
    const tab = this.byId(id);
    if (!tab) return;
    tab.status = "rendered";
    tab.rendition = null;
    tab.display = display;
    tab.shortLabel = trim(display, 22);
    this.notify();
  }
```

`addressBar.ts`: add the `onProfile` hook and branch.

```ts
export interface AddressBarHooks {
  onSubmit: (address: string, query: string) => void;
  onProfile: (input: import("../address").AddressInput) => void;
  onInvalid: (msg: string) => void;
}
// replace the body of submit():
  const submit = (): void => {
    const parsed = parseAddressInput(input.value);
    if (!parsed) {
      hooks.onInvalid("enter a 64-hex address or an @handle@domain");
      return;
    }
    if (parsed.kind === "hex") {
      input.value = parsed.address + parsed.query;
      hooks.onSubmit(parsed.address, parsed.query);
    } else {
      hooks.onProfile(parsed);
    }
  };
// update the import at the top:
import { parseAddressInput } from "../address";
```

`controller.ts`: add `startProfile` + wire `onProfile`, and a reusable `openProfile`. Add imports:

```ts
import { resolveProfile, relayFromShareUri, type ProfileInput } from "./profile/open";
import { renderProfilePage, type ProfilePageHandlers } from "./profile/page";
import { lookupHandle } from "./fediverse/api";
import { fetchProfile, fetchAvatar, pairAccept, sendDm } from "./chat/api";
import { probeEtchit, openEtchitProfile } from "./profile/handoff";
```

Add the address-bar hook (in the `mountAddressBar` call):

```ts
  const bar: AddressBarApi = mountAddressBar(input, button, {
    onSubmit: (addr, query) => submit(addr, store, stageEl, query),
    onProfile: (parsed) => {
      const input: ProfileInput =
        parsed.kind === "handle"
          ? { kind: "handle", handle: parsed.handle }
          : { kind: "agentId", agentId: parsed.agentId };
      openProfile(input, store, stageEl);
    },
    onInvalid: (msg) => { statusEl.textContent = msg; },
  });
```

Add `openProfile` + `startProfile` (module-level functions, mirroring `submit`/`startIn`):

```ts
// The profile handlers close over the chat panel + reader navigation.
function profileHandlers(store: TabStore, stage: HTMLElement, chat: ChatPanelApi | null): ProfilePageHandlers {
  return {
    onAutonomi: (uri) => { const p = parseAutonomiUrl(uri); if (p) submit(p.address, store, stage, p.query); },
    onMessage: (m) => {
      if (!m.agentId) return;
      const go = (id: string) => { void chat?.openDm(id); };
      if (m.shareUri) pairAccept(m.shareUri).then((r) => go(r.agentIdHex)).catch(() => go(m.agentId as string));
      else go(m.agentId);
    },
    onInvite: (m) => { if (m.agentId) void chat?.openInvite?.(m.agentId, m.shareUri ?? null); },
    onShare: (m) => { if (m.agentId) qrModal.open(m.agentId, m.display); },
    onEditEtch: () => { void openEtchitProfile().catch(() => {}); },
    onGetEtch: () => { void confirmOpen("https://etchit.io"); },
    confirmOpen: (url) => { void confirmOpen(url); },
  };
}

export function openProfile(input: ProfileInput, store: TabStore, stage: HTMLElement): void {
  const canonical = input.kind === "handle" ? input.handle : `profile:${input.agentId}`;
  const existing = store.findByAddress(canonical);
  const tab = existing ?? (store.active()?.status === "empty" ? store.active()! : store.createEmpty(buildStageRoot(stage)));
  store.activate(tab.id);
  startProfile(tab, canonical, input, store);
}

function startProfile(tab: { id: string; root: HTMLElement }, canonical: string, input: ProfileInput, store: TabStore): void {
  findMascotIn(tab.root)?.dispose();
  const mascot = mountMascot();
  tab.root.replaceChildren(mascot.element);
  store.startFetch(tab.id, canonical);
  void resolveProfile(input, { lookupHandle, fetchProfile })
    .then((model) => {
      findMascotIn(tab.root)?.dispose();
      renderProfilePage(model, tab.root, profileHandlers(store, /*stage*/ tab.root.parentElement as HTMLElement, chatRef()), fetchAvatar);
      store.renderProfile(tab.id, model.handle ?? model.display);
    });
}
```

Note: `chatRef()` returns the module-scoped `chat` (already captured in `init`); expose it via a small accessor `let chatPanel: ChatPanelApi | null = null;` set where `chat` is assigned, and `function chatRef() { return chatPanel; }`. Canonical handle tabs display the handle; agent-id tabs display the resolved name. Back/history/dedupe come free from `startFetch` + `findByAddress`.

- [ ] **Step 4: Run to verify pass**

Run: `(cd apps/fetchit-desktop && npx tsc --noEmit && npm run test:run -- tabs)`
Expected: PASS. (tsc surfaces any handler-shape mismatch; fix against the `ProfilePageHandlers` interface from Task 4.)

- [ ] **Step 5: Commit**

```bash
git add apps/fetchit-desktop/src/tabs.ts apps/fetchit-desktop/src/ui/addressBar.ts apps/fetchit-desktop/src/controller.ts
git commit -s -m "feat(desktop): profile tab front door (address bar + controller)"
```

---

## Task 9: Entry points (lookup card, DM modal)

**Files:**
- Modify: `apps/fetchit-desktop/src/fediverse/lookup.ts`
- Modify: `apps/fetchit-desktop/src/chat/profileCard.ts`
- Modify: `apps/fetchit-desktop/src/controller.ts`

- [ ] **Step 1: Write the failing test** (append to a `lookup.test.ts`; create if absent)

```ts
import { renderActorCard } from "./lookup";

it("verified card offers View profile and routes the handle", () => {
  let seen: string | null = null;
  const dto = { kind: "verified" as const, handle: "@josh@etchit.io", actorUrl: "u",
    agentIdHex: "a".repeat(64), displayName: "Josh", bio: "hi",
    shareUri: "fetchit://share/v3/x", previousAgentIdHex: null, verifyFailure: null };
  const card = renderActorCard(dto, { onOpenDm: () => {}, onViewProfile: (h) => { seen = h; } });
  (card.querySelector("[data-act=view-profile]") as HTMLElement).click();
  expect(seen).toBe("@josh@etchit.io");
});
```

- [ ] **Step 2: Run to verify fail**

Run: `(cd apps/fetchit-desktop && npm run test:run -- lookup)`
Expected: FAIL, `onViewProfile` not on the handlers type / button absent.

- [ ] **Step 3: Implement** — `lookup.ts`: extend `LookupHandlers` and add the button to every card.

```ts
export interface LookupHandlers {
  onOpenDm: (agentIdHex: string) => void;
  onViewProfile: (handle: string) => void;
}
// in renderActorCard, before `return card;`:
  const view = document.createElement("button");
  view.type = "button";
  view.className = "actor-card__view-btn";
  view.dataset.act = "view-profile";
  view.textContent = "View profile";
  view.addEventListener("click", () => handlers.onViewProfile(dto.handle));
  card.append(view);
```

`profileCard.ts`: add an "Open full profile" button. Extend `ProfileCardOpts` with `onOpenFullProfile: (agentId: string) => void` and append the button in `renderLoaded` (after the name):

```ts
  const full = document.createElement("button");
  full.type = "button";
  full.className = "chat-profile__full";
  full.textContent = "Open full profile";
  full.addEventListener("click", () => { closeCard(); opts.onOpenFullProfile(opts.agentId); });
  body.appendChild(full);
```

`controller.ts`: wire both handlers to `openProfile`. The fediverse pane's `mountLookup`/`renderActorCard` handlers gain `onViewProfile: (handle) => openProfile({ kind: "handle", handle }, store, stageEl)`. The chat modal's `viewProfile` (in `conversation.ts` via `openProfileCard`) passes `onOpenFullProfile: (agentId) => { chat?.close(); openProfile({ kind: "agentId", agentId }, store, stageEl); }`. Thread `onOpenFullProfile` through the `ConversationHandlers` -> `openProfileCard` call sites (mirror the existing `onAutonomi` threading).

- [ ] **Step 4: Run to verify pass**

Run: `(cd apps/fetchit-desktop && npx tsc --noEmit && npm run test:run -- lookup profileCard)`
Expected: PASS (fix any existing `renderActorCard`/`openProfileCard` call site the new required field breaks; tsc lists them).

- [ ] **Step 5: Commit**

```bash
git add apps/fetchit-desktop/src/fediverse/lookup.ts apps/fetchit-desktop/src/chat/profileCard.ts apps/fetchit-desktop/src/chat/conversation.ts apps/fetchit-desktop/src/controller.ts
git commit -s -m "feat(desktop): View profile entry points (lookup card + chat modal)"
```

---

## Task 10: "View my profile" entry + own-profile relay

**Files:**
- Modify: `apps/fetchit-desktop/src/settings.ts`
- Modify: `apps/fetchit-desktop/src/controller.ts`

- [ ] **Step 1: Write the failing test** (append to `settings.test.ts`; create if absent)

```ts
import { mountSettings } from "./settings";

it("settings exposes a View my profile control", () => {
  const host = document.createElement("div");
  mountSettings(host, {
    onNavigate: () => {}, onIdleChanged: () => {}, onShareBookmark: () => {},
    onShareBookmarkList: () => {}, onViewMyProfile: () => {},
  });
  expect(host.querySelector("[data-act=view-my-profile]")).not.toBeNull();
});
```

- [ ] **Step 2: Run to verify fail**

Run: `(cd apps/fetchit-desktop && npm run test:run -- settings)`
Expected: FAIL.

- [ ] **Step 3: Implement** — add `onViewMyProfile: () => void` to the settings options type; render a button with `dataset.act = "view-my-profile"` in the profile/identity section that calls `opts.onViewMyProfile()`. In `controller.ts` wire it:

```ts
    onViewMyProfile: () => {
      settings.close();
      void invoke<string>("chat_self_agent_id")
        .then((agentId) => openProfile({ kind: "agentId", agentId, isSelf: true }, store, stageEl))
        .catch((e) => { statusEl.textContent = errorMessage(e); });
    },
```

(Confirm the self-agent-id command name against `src-tauri`; if it differs, reuse the command the chat panel already uses to label the user's own identity. If none exists, the chat client exposes the agent id via the existing self-profile path used by `self_profile_record` in `chat.rs`.)

- [ ] **Step 4: Run to verify pass**

Run: `(cd apps/fetchit-desktop && npx tsc --noEmit && npm run test:run -- settings)`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/fetchit-desktop/src/settings.ts apps/fetchit-desktop/src/controller.ts
git commit -s -m "feat(desktop): View my profile entry from settings"
```

---

## Task 11: Profile-manifest detection banner

**Files:**
- Modify: `apps/fetchit-desktop/src/renderers/json.ts`
- Modify: `apps/fetchit-desktop/src/renderers/dispatch.ts`
- Modify: `apps/fetchit-desktop/src/controller.ts`

- [ ] **Step 1: Write the failing test** (`json.test.ts`, create if absent)

```ts
import { renderJson } from "./json";

const manifest = JSON.stringify({
  version: 1, agent_id: "a".repeat(64), display_name: "Josh",
  ml_dsa_pubkey: "AA", sig: "BB", issued_at_ms: 1,
});

it("shows a profile banner for manifest-shaped JSON and routes to the profile", () => {
  let seen: string | null = null;
  const into = document.createElement("div");
  renderJson({ kind: "json", pretty: manifest } as any, into, (id) => { seen = id; });
  (into.querySelector("[data-act=view-as-profile]") as HTMLElement).click();
  expect(seen).toBe("a".repeat(64));
});

it("shows no banner for ordinary JSON", () => {
  const into = document.createElement("div");
  renderJson({ kind: "json", pretty: '{"hello":1}' } as any, into, () => {});
  expect(into.querySelector("[data-act=view-as-profile]")).toBeNull();
});
```

- [ ] **Step 2: Run to verify fail**

Run: `(cd apps/fetchit-desktop && npm run test:run -- json)`
Expected: FAIL, `renderJson` takes 2 args.

- [ ] **Step 3: Implement** (`json.ts`)

```ts
import type { Rendition } from "../types";
import { el } from "../format";

const HEX_64 = /^[0-9a-f]{64}$/i;

function profileAgentId(pretty: string): string | null {
  try {
    const v = JSON.parse(pretty) as Record<string, unknown>;
    if (v.version === 1 && typeof v.agent_id === "string" && HEX_64.test(v.agent_id)
      && typeof v.sig === "string" && typeof v.ml_dsa_pubkey === "string") {
      return v.agent_id.toLowerCase();
    }
  } catch { /* not json-of-interest */ }
  return null;
}

export function renderJson(
  r: Extract<Rendition, { kind: "json" }>,
  into: HTMLElement,
  onViewProfile?: (agentId: string) => void,
): void {
  const agentId = profileAgentId(r.pretty);
  if (agentId && onViewProfile) {
    const banner = document.createElement("div");
    banner.className = "json-profile-banner";
    banner.textContent = "This looks like a profile. ";
    const view = document.createElement("button");
    view.type = "button";
    view.dataset.act = "view-as-profile";
    view.textContent = "View as profile page";
    view.addEventListener("click", () => onViewProfile(agentId));
    banner.appendChild(view);
    into.appendChild(banner);
  }
  into.appendChild(el("pre", r.pretty));
}
```

`dispatch.ts`: thread the callback.

```ts
export function render(
  r: Rendition, into: HTMLElement, address: string, query = "",
  onViewProfile?: (agentId: string) => void,
): void {
  // ...
  case "json":
    renderJson(r, into, onViewProfile);
    return;
```

`controller.ts`: pass it where `renderRendition` is called in `runFetch`.

```ts
    renderRendition(r, root, addr, query, (agentId) => openProfile({ kind: "agentId", agentId }, store, stageEl));
```

(Add a `.json-profile-banner` block to `styles.css`: `margin-bottom:10px; color: var(--ash);` with the button in `--copper`.)

- [ ] **Step 4: Run to verify pass**

Run: `(cd apps/fetchit-desktop && npx tsc --noEmit && npm run test:run -- json)`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/fetchit-desktop/src/renderers/json.ts apps/fetchit-desktop/src/renderers/dispatch.ts apps/fetchit-desktop/src/controller.ts apps/fetchit-desktop/src/styles.css
git commit -s -m "feat(desktop): profile-manifest detection banner in the JSON view"
```

---

## Task 12: Bookmark label + full gates + integration sweep

**Files:**
- Modify: `apps/fetchit-desktop/src/bookmarks.ts` (label derivation for `profile:`/handle addresses)
- Modify: `apps/fetchit-desktop/src/controller.ts` (back/dedup confirmation)

- [ ] **Step 1: Write the failing test** (append to `bookmarks.test.ts`)

```ts
import { deriveLabel } from "./bookmarks";

it("labels a profile address with its display name when present", () => {
  // deriveLabel(rendition, address) — profile tabs have a null rendition,
  // so the label falls back to the address; a handle address is already
  // human-friendly.
  expect(deriveLabel(null, "@josh@etchit.io")).toBe("@josh@etchit.io");
});
```

- [ ] **Step 2: Run to verify fail / confirm current behaviour**

Run: `(cd apps/fetchit-desktop && npm run test:run -- bookmarks)`
Expected: FAIL if `deriveLabel` does not already pass a handle address through; otherwise adjust the assertion to the actual contract and make the handle case explicit.

- [ ] **Step 3: Implement** — ensure `deriveLabel(null, address)` returns a handle address verbatim and a `profile:<id>` address as a short id; no rendition-kind assumptions. Keep the change minimal and within the existing function.

- [ ] **Step 4: Full gates**

```bash
(cd apps/fetchit-desktop && npx tsc --noEmit && npm run test:run)
(cd apps/fetchit-desktop/src-tauri && cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check)
```
Expected: all green. Manually drive the two integration paths in `npm run tauri dev`: (a) fediverse pane lookup -> View profile -> banner page with gallery; (b) DM header -> Open full profile -> page; (c) type `@handle@domain` in the address bar -> page; (d) bookmark a profile tab, reload, reopen from the bookmark.

- [ ] **Step 5: Commit**

```bash
git add apps/fetchit-desktop/src
git commit -s -m "feat(desktop): profile bookmark labels + integration gates"
```

---

## Self-review notes (author)

- **Spec coverage:** universal front door = Tasks 1/8; banner layout = Task 4; verified badge + honest-claim states = Task 4 (+ section 6 copy); etchings gallery = Task 5; share QR = Task 4/8 (`onShare` -> qrModal); view-my-own = Task 10; manifest detection = Task 11; modal demotion = Task 9; etch/it handoff = Tasks 6/7; relay-hint threading = Task 2; security (textContent, allowlisted links, no new I/O) = Tasks 4/5 + the resolver's reuse of the three audited commands. Out-of-scope items (core Rendition, Android, lease mechanics) are correctly absent.
- **Type consistency:** `AddressInput` (T1) -> addressBar/controller (T8); `ProfilePageModel`/`resolveProfile`/`relayFromShareUri` (T3) -> page (T4-6) + controller (T8); `ProfilePageHandlers` (T4) stable across T5/6/8; `fetchProfile(agentId, relay?)` (T2) -> resolver (T3); `renderProfile` (T8) on TabStore; `onViewProfile` shape identical in lookup (T9), json (T11), settings (T10).
- **Open confirmations flagged inline (not placeholders, version-pin checks):** the `tauri-plugin-opener` API path (T7), the self-agent-id command name (T10), and the exact `deriveLabel` signature (T12) are each "match what the crate/codebase already uses" notes with a named fallback, not undefined work.
