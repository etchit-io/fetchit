import { invoke } from "@tauri-apps/api/core";
import type { Rendition } from "./types";
import { TabStore } from "./tabs";
import { render as renderRendition } from "./renderers/dispatch";
import { mountTabStrip } from "./ui/tabStrip";
import { mountAddressBar, type AddressBarApi } from "./ui/addressBar";
import { bindKeyboard } from "./ui/keyboard";
import { initMediaBase } from "./mediaUrl";
import { parseAutonomiUrl, type AddressInput } from "./address";
import { resolveProfile, type ProfileInput } from "./profile/open";
import { renderProfilePage, type ProfilePageHandlers } from "./profile/page";
import { openEtchitProfile } from "./profile/handoff";
import { lookupHandle } from "./fediverse/api";
import { fetchProfile, fetchAvatar, pairAccept, identity as chatIdentity } from "./chat/api";
import { chatConfirm } from "./chat/confirmDialog";
import { mountSettings } from "./settings";
import { mountQrModal } from "./ui/qrModal";
import { mountDownloadProgress } from "./ui/downloadProgress";
import { findMascotIn, mountMascot } from "./ui/mascot";
import { icon } from "./ui/icons";
import { mountAddressBarSuggestions } from "./ui/addressBarSuggestions";
import { addBookmark, deriveLabel, deriveTitle, isBookmarked, removeBookmark } from "./bookmarks";
import { encodeBookmarksForShare } from "./bookmarkShare";
import { getCurrent as getCurrentDeepLink, onOpenUrl } from "@tauri-apps/plugin-deep-link";
import { startIdleTracker } from "./idle";
import { mountChatPanel, type ChatPanelApi } from "./chat";
import { initOnboarding } from "./onboarding/welcome";
import { mountFediversePanel } from "./fediverse/panel";
import { bindFediverseEvents } from "./fediverse/events";
import { DEMO_CITY_INDEX, buildEmptyState } from "./emptyState";

const HEX_64 = /^[0-9a-fA-F]{64}$/;

export async function init(): Promise<void> {
  // Resolve the local media-server URL before any render can happen.
  // Renderers and the rewriter rely on it synchronously.
  try {
    await initMediaBase();
  } catch (err) {
    console.error("[fetchit] media server URL unavailable:", err);
  }
  const input = need<HTMLInputElement>("addr");
  const button = need<HTMLButtonElement>("go");
  const backBtn = need<HTMLButtonElement>("back-toggle");
  const settingsBtn = need<HTMLButtonElement>("settings-toggle");
  const settingsHost = need<HTMLElement>("settings");
  const bookmarkBtn = need<HTMLButtonElement>("bookmark-toggle");
  const shareBtn = need<HTMLButtonElement>("share-toggle");
  const chatBtn = need<HTMLButtonElement>("chat-toggle");
  const chatHost = need<HTMLElement>("chat-panel");
  const fediverseBtn = need<HTMLButtonElement>("fediverse-toggle");
  const fediverseHost = need<HTMLElement>("fediverse-panel");
  const qrHost = need<HTMLElement>("qr-modal");
  const statusEl = need<HTMLElement>("status");
  const stripEl = need<HTMLElement>("tabs");
  const stageEl = need<HTMLElement>("stage");
  const setBookmarkState = (on: boolean): void => {
    bookmarkBtn.dataset.bookmarked = on ? "true" : "false";
  };

  // Hydrate the header chrome with the shared inline-SVG icon set. Each
  // button carries its own aria-label/title, so the icons are decorative.
  backBtn.appendChild(icon("back"));
  bookmarkBtn.appendChild(icon("bookmark"));
  shareBtn.appendChild(icon("share"));
  chatBtn.appendChild(icon("chat"));
  fediverseBtn.appendChild(icon("fediverse"));
  settingsBtn.appendChild(icon("settings"));

  // Idle tracker — drops the Autonomi client + clears caches after the
  // user-configured timeout of no mouse / keyboard activity. The current
  // policy is read from settings.json; the settings panel can update it live
  // via `onIdleChanged`.
  const idle = startIdleTracker();
  void invoke<{ timeoutMinutes: number }>("idle_policy")
    .then((p) => idle.setTimeoutMinutes(p.timeoutMinutes))
    .catch(() => {});

  const qrModal = mountQrModal(qrHost);

  const settings = mountSettings(settingsHost, {
    onNavigate: (addr) => {
      settings.close();
      submit(addr, store, stageEl);
    },
    onIdleChanged: (m) => idle.setTimeoutMinutes(m),
    onShareBookmark: (addr, label) => {
      settings.close();
      qrModal.open(addr, label);
    },
    onShareBookmarkList: (bookmarks) => {
      try {
        const url = encodeBookmarksForShare(bookmarks);
        settings.close();
        const count = bookmarks.length;
        const summary = count === 1 ? "1 bookmark" : `${count} bookmarks`;
        qrModal.openImport(url, summary);
      } catch (err) {
        console.error("[fetchit] share bookmark list:", err);
      }
    },
    onViewMyProfile: () => {
      settings.close();
      void chatIdentity()
        .then((id) => openProfile({ kind: "agentId", agentId: id.agent_id, isSelf: true }))
        .catch((e) => { statusEl.textContent = errorMessage(e); });
    },
  });
  settingsBtn.addEventListener("click", () => void settings.toggle());

  const openShare = (): void => {
    const active = store.active();
    const addr = active?.address;
    if (!addr) return;
    qrModal.open(addr, deriveTitle(active?.rendition));
  };
  shareBtn.addEventListener("click", openShare);

  // Master feature gate for the chat surface. The Tauri backend
  // returns `false` for v1 release builds unless FETCHIT_CHAT_ENABLED
  // is set or chatEnabled is true in settings.json. Failing the
  // query defaults to the build-time DEV flavour so `npm run tauri
  // dev` keeps the panel visible without extra config.
  const chatOn = await invoke<boolean>("chat_feature_enabled").catch(
    () => import.meta.env.DEV,
  );
  // Captured at module level (within the closure) so the keyboard
  // shortcut handler below can call into the panel when it's mounted
  // and no-op when it isn't.
  let chat: ChatPanelApi | null = null;
  let chatSurfaceMounted = false;
  // Mounts the chat + fediverse surfaces. Runs at boot when the
  // feature resolves on, or live from the first-run onboarding flow
  // after set_chat_enabled succeeds. Idempotent.
  const mountChatSurface = (): void => {
    if (chatSurfaceMounted) return;
    chatSurfaceMounted = true;
    chatBtn.hidden = false;
    fediverseBtn.hidden = false;
    const chatBadge = document.createElement("span");
    chatBadge.className = "chat-toggle__badge";
    chatBadge.hidden = true;
    chatBtn.appendChild(chatBadge);
    let lastUnread = 0;
    const renderChatBadge = (count: number): void => {
      // Hide entirely while the panel is open — the user is plainly
      // already reading, no need to nag with a count.
      if (chat?.isOpen() || count <= 0) {
        chatBadge.hidden = true;
        chatBtn.removeAttribute("data-unread");
        return;
      }
      chatBadge.hidden = false;
      chatBadge.textContent = count > 99 ? "99+" : String(count);
      chatBtn.setAttribute("data-unread", "true");
    };

    chat = mountChatPanel(chatHost, {
      onAutonomi: (uri) => {
        const parsed = parseAutonomiUrl(uri);
        if (parsed) {
          chat?.close();
          submit(parsed.address, store, stageEl, parsed.query);
        }
      },
      onClose: () => {
        // Re-render badge in case unread accrued while the panel was
        // open (user could've left the panel on a different conv).
        // Defer one tick so chat.isOpen() reports the new state first.
        setTimeout(() => renderChatBadge(lastUnread), 0);
      },
      onOpenFullProfile: (agentId) => openProfile({ kind: "agentId", agentId }),
      onUnreadChange: (n) => {
        lastUnread = n;
        renderChatBadge(n);
      },
    });
    chatBtn.addEventListener("click", () => {
      void chat?.toggle().then(() => renderChatBadge(lastUnread));
    });

    // M4 fediverse pane: the public read-feed surface. The event
    // bridge drains the chat client's inbound bridged-post broadcast
    // (Client::subscribe_to_public_posts) and renders each as an inert
    // card. Standalone overlay; opening it leaves chat as-is.
    const fediverse = mountFediversePanel(fediverseHost, {
      onClose: () => {
        /* nothing to reconcile on close */
      },
      onOpenDm: (agentIdHex) => {
        // Hand off to LIT Chat: the lookup card already imported the
        // contact, so close the public pane and land on the DM.
        fediverse.close();
        void chat?.openDm(agentIdHex);
      },
      onViewProfile: (handle) => openProfile({ kind: "handle", handle }),
    });
    void bindFediverseEvents(fediverse);
    fediverseBtn.addEventListener("click", () => fediverse.toggle());
  };
  if (!chatOn) {
    chatBtn.hidden = true;
    chatHost.hidden = true;
    // The fediverse pane consumes the chat client's public-post
    // broadcast, so it shares the chat feature gate.
    fediverseBtn.hidden = true;
    fediverseHost.hidden = true;
  } else {
    mountChatSurface();
  }

  // First-run welcome overlay: one name question, chat enabled live on
  // Start (no restart), Skip just marks done. Mounted over the live
  // app; gated by the persisted onboarding_done flag.
  void initOnboarding(need<HTMLElement>("onboarding"), {
    onChatStart: async () => {
      mountChatSurface();
      if (chat && !chat.isOpen()) {
        await chat.toggle();
      }
    },
  });

  const toggleBookmark = async (): Promise<void> => {
    const active = store.active();
    if (!active || !active.address) return;
    if (active.status === "loading") return;
    const addr = active.address;
    const already = await isBookmarked(addr).catch(() => false);
    if (already) {
      await removeBookmark(addr).catch(() => {});
      setBookmarkState(false);
    } else {
      const label = deriveLabel(active.rendition, addr);
      await addBookmark(addr, label).catch(() => {});
      setBookmarkState(true);
    }
    if (settings.isOpen()) await settings.refreshBookmarks();
    void suggestions.refresh();
  };
  bookmarkBtn.addEventListener("click", () => void toggleBookmark());

  // Top-bar back button — same handler as the keyboard binding (Alt+Left).
  // EPUB / PDF / HTML renderers occupy the full stage and intercept their
  // own scrolling, so the toolbar control is the only DOM-accessible back
  // trigger from inside those renderers.
  backBtn.addEventListener("click", () => backNavigate(store));

  const store = new TabStore();
  mountDownloadProgress(store);

  // fetch>it has no external-browser capability (see chat/conversation.ts):
  // external links are copied to the clipboard behind a confirm rather than
  // pretending to open. Shared by the profile page's website links and the
  // "Get etch/it" call-to-action.
  const confirmOpenExternal = (url: string): void => {
    void chatConfirm({
      title: "Copy link",
      message:
        "fetch>it doesn't open external sites, so this copies the link to "
        + "your clipboard:\n" + url,
      confirmLabel: "Copy link",
    }).then((ok) => {
      if (ok) void navigator.clipboard.writeText(url).catch(() => {});
    });
  };

  // Profile (shell-route) page handlers. Closures so they capture the live
  // `chat` panel api, `qrModal`, and `store` without threading accessors.
  const profileHandlers: ProfilePageHandlers = {
    onAutonomi: (uri) => {
      const parsed = parseAutonomiUrl(uri);
      if (parsed) submit(parsed.address, store, stageEl, parsed.query);
    },
    onMessage: (model) => {
      if (model.shareUri) {
        void pairAccept(model.shareUri)
          .then((r) => chat?.openDm(r.agentIdHex))
          .catch(() => {});
      } else if (model.agentId) {
        void chat?.openDm(model.agentId);
      }
    },
    onInvite: (model) => {
      // No public "invite agent to group" surface on the chat panel; the
      // honest minimum is to ensure the contact exists (pairAccept the
      // share URI) then land on them so the user can use chat's own group
      // flow. Reuses real apis; invents nothing.
      if (model.shareUri) {
        void pairAccept(model.shareUri)
          .then((r) => chat?.openDm(r.agentIdHex))
          .catch(() => {});
      } else if (model.agentId) {
        void chat?.openDm(model.agentId);
      }
    },
    onShare: (model) => {
      if (model.agentId) qrModal.open(model.agentId, model.display);
    },
    onEditEtch: () => {
      void openEtchitProfile().catch(() => {});
    },
    onGetEtch: () => confirmOpenExternal("https://etchit.io"),
    confirmOpen: confirmOpenExternal,
  };

  // Resolve + render a profile (handle or agent-id) into a tab. Mirrors
  // `submit`: dedupe on the canonical address, reuse an empty active tab or
  // create one, then `startProfile` does the mascot + resolve + render.
  const openProfile = (input: ProfileInput): void => {
    const canonical =
      input.kind === "handle" ? input.handle : `profile:${input.agentId}`;
    const existing = store.findByAddress(canonical);
    if (existing) {
      store.activate(existing.id);
      if (existing.status === "error") void startProfile(existing, input, canonical);
      return;
    }
    const active = store.active();
    const target =
      active && active.status === "empty" ? active : store.createEmpty(buildStageRoot(stageEl));
    void startProfile(target, input, canonical);
  };

  const startProfile = async (
    tab: { id: string; root: HTMLElement },
    input: ProfileInput,
    canonical: string,
  ): Promise<void> => {
    findMascotIn(tab.root)?.dispose();
    const mascot = mountMascot();
    tab.root.replaceChildren(mascot.element);
    store.startFetch(tab.id, canonical);
    const model = await resolveProfile(input, { lookupHandle, fetchProfile });
    findMascotIn(tab.root)?.dispose();
    renderProfilePage(model, tab.root, profileHandlers, fetchAvatar);
    // An error model marks the tab errored so a re-open re-resolves it
    // (mirrors `submit`'s retry-on-error dedupe); any other state renders.
    if (model.state === "error") {
      store.setError(tab.id, model.error ?? "couldn't load this profile");
    } else {
      store.renderProfile(tab.id, model.handle ?? model.display);
    }
  };

  const onProfileInput = (parsed: AddressInput): void => {
    if (parsed.kind === "hex") {
      submit(parsed.address, store, stageEl, parsed.query);
      return;
    }
    const input: ProfileInput =
      parsed.kind === "handle"
        ? { kind: "handle", handle: parsed.handle }
        : { kind: "agentId", agentId: parsed.agentId };
    openProfile(input);
  };

  const bar: AddressBarApi = mountAddressBar(input, button, {
    onSubmit: (addr, query) => submit(addr, store, stageEl, query),
    onProfile: onProfileInput,
    onInvalid: (msg) => {
      statusEl.textContent = msg;
    },
  });
  const suggestions = mountAddressBarSuggestions({
    input,
    onSelect: (addr) => submit(addr, store, stageEl),
  });

  const newTab = (): void => {
    const root = buildStageRoot(stageEl);
    root.appendChild(buildEmptyState(() => submit(DEMO_CITY_INDEX, store, stageEl)));
    store.createEmpty(root);
    bar.focus();
  };

  const refresh = (): void => {
    const active = store.active();
    if (!active || !active.address) return;
    startIn(active, active.address, store, active.query, false);
  };

  const smartPaste = (): void => {
    void navigator.clipboard.readText().then((text) => {
      const parsed = parseAutonomiUrl(text);
      if (!parsed) return;
      bar.setValue(parsed.address + parsed.query);
      submit(parsed.address, store, stageEl, parsed.query);
    }).catch(() => {});
  };

  const smartCopy = (): void => {
    const addr = store.active()?.address;
    if (!addr) return;
    void navigator.clipboard.writeText(addr).catch(() => {});
    statusEl.textContent = "address copied to clipboard";
    setTimeout(() => {
      if (statusEl.textContent === "address copied to clipboard") statusEl.textContent = "";
    }, 1200);
  };

  const blurFocused = (): void => {
    if (settings.isOpen()) {
      settings.close();
      return;
    }
    const el = document.activeElement;
    if (el instanceof HTMLElement) el.blur();
  };

  mountTabStrip(stripEl, store, newTab);
  bindKeyboard(store, {
    newTab,
    refresh,
    back: () => backNavigate(store),
    focusAddress: () => bar.focus(),
    blurFocused,
    smartPaste,
    smartCopy,
    openSettings: () => void settings.open(),
    openShare,
    toggleBookmark: () => void toggleBookmark(),
    toggleChat: () => void chat?.toggle(),
  });

  let lastBookmarkAddr: string | null = null;
  store.subscribe(() => {
    const active = store.active();
    for (const t of store.list()) {
      t.root.classList.toggle("is-active", !!active && t.id === active.id);
    }
    // Profile (shell-route) tabs carry a friendly `display` (the handle or
    // name) so the bar shows that instead of the raw `profile:<id>` address.
    if (!bar.isFocused()) {
      bar.setValue(
        active && active.address
          ? active.display ?? active.address + active.query
          : "",
      );
    }
    statusEl.textContent = statusFor(active);
    button.disabled = active?.status === "loading";
    bookmarkBtn.disabled = !active?.address || active.status === "loading";
    shareBtn.disabled = !active?.address || active.status === "loading";
    // Back is enabled only when the active tab has history we can pop.
    backBtn.disabled = !active || (active.history?.length ?? 0) === 0;
    const addr = active?.address ?? null;
    if (addr !== lastBookmarkAddr) {
      lastBookmarkAddr = addr;
      if (!addr) {
        setBookmarkState(false);
      } else {
        void isBookmarked(addr).then((on) => {
          if (lastBookmarkAddr === addr) setBookmarkState(on);
        }).catch(() => setBookmarkState(false));
      }
    }
  });

  bindIframeMessages(store, stageEl);

  // Deep-link handler — clicks on `autonomi://<addr>` (or `fetchit://<addr>`)
  // in any other app (email, chat, browser, QR scanner) route to fetch>it via
  // the OS scheme registration. `getCurrent` returns the URL the app was
  // launched with (if any); `onOpenUrl` fires for subsequent links that come
  // in while the app is running.
  const handleDeepLink = (url: string): void => {
    const parsed = parseAutonomiUrl(url);
    if (!parsed) return;
    bar.setValue(parsed.address + parsed.query);
    submit(parsed.address, store, stageEl, parsed.query);
  };
  void getCurrentDeepLink()
    .then((urls) => {
      if (urls) for (const u of urls) handleDeepLink(u);
    })
    .catch(() => {});
  void onOpenUrl((urls) => {
    for (const u of urls) handleDeepLink(u);
  }).catch(() => {});

  bar.focus();
}

// Dev-only diagnostic forwarder. In production builds (vite build) the early
// return makes this a no-op — no IPC, no daemon-log spam. Mirrors protocol.rs's
// `diag!` macro on the Rust side; the matching no-op there is what makes both
// safe to keep in committed code.
function dlog(line: string): void {
  if (!import.meta.env.DEV) return;
  void invoke("log", { line }).catch(() => {});
}

// In-iframe address links postMessage one of three shapes:
//   { kind: "fetchit:open", address, target } — link click, navigate or new-tab;
//   { kind: "fetchit:back" }                  — magic <a href="fetchit://back">;
//   { kind: "fetchit:log",  text }            — dev-only diagnostic.
function bindIframeMessages(store: TabStore, stage: HTMLElement): void {
  window.addEventListener("message", (e) => {
    const data = e.data as
      | { kind?: unknown; address?: unknown; target?: unknown; text?: unknown }
      | null;
    if (!data || typeof data !== "object") return;
    if (data.kind === "fetchit:log") {
      if (typeof data.text === "string") dlog(`[iframe] ${data.text}`);
      return;
    }
    if (data.kind === "fetchit:back") {
      dlog(`[parent] back-link received`);
      backNavigate(store);
      return;
    }
    if (data.kind !== "fetchit:open") return;
    const addr = typeof data.address === "string" ? data.address : "";
    if (!HEX_64.test(addr)) {
      dlog(`[parent] postMessage rejected: bad address ${String(data.address).slice(0, 16)}`);
      return;
    }
    const wantsNew = data.target === "new";
    dlog(`[parent] navigate addr=${addr.slice(0, 8)}… newTab=${wantsNew}`);
    navigate(addr.toLowerCase(), store, stage, wantsNew);
  });
}

function backNavigate(store: TabStore): void {
  const active = store.active();
  if (!active) return;
  const prev = store.popHistory(active.id);
  if (!prev) {
    dlog(`[parent] back ignored: no history`);
    return;
  }
  dlog(`[parent] back to addr=${prev.slice(0, 8)}…`);
  startIn(active, prev, store, "", false);
}

function navigate(addr: string, store: TabStore, stage: HTMLElement, newTab: boolean): void {
  if (newTab) {
    startIn(store.createEmpty(buildStageRoot(stage)), addr, store);
    return;
  }
  const active = store.active();
  const target = active ?? store.createEmpty(buildStageRoot(stage));
  startIn(target, addr, store);
}

function submit(addr: string, store: TabStore, stage: HTMLElement, query = ""): void {
  const existing = store.findByAddress(addr);
  if (existing) {
    store.activate(existing.id);
    if (existing.status === "error" || query !== (existing.query ?? "")) {
      startIn(existing, addr, store, query);
    }
    return;
  }
  const active = store.active();
  const target = active && active.status === "empty" ? active : store.createEmpty(buildStageRoot(stage));
  startIn(target, addr, store, query);
}

function startIn(
  tab: { id: string; root: HTMLElement },
  addr: string,
  store: TabStore,
  query = "",
  recordHistory = true,
): void {
  // No explicit cancel here: registering the new fetch supersedes (and
  // cancels) any prior in-flight fetch for this tab atomically on the
  // Rust side, so a refetch never races a separate cancel message.
  // If a previous mascot is still mounted (e.g. user re-submitted the
  // address while the first fetch was in flight) dispose it so its
  // idle-behavior timers stop before we mount a fresh one.
  findMascotIn(tab.root)?.dispose();
  const mascot = mountMascot();
  tab.root.replaceChildren(mascot.element);
  store.startFetch(tab.id, addr, recordHistory, query);
  void runFetch(addr, tab.id, tab.root, store, query);
}

// Session flag — true once any fetch has succeeded in this app session.
// The first fetch waits on bootstrap + peer connect; subsequent fetches
// reuse the live client. Gates the bootstrap-hint status string in
// `statusFor`.
let firstFetchSucceeded = false;

async function runFetch(
  addr: string,
  id: string,
  root: HTMLElement,
  store: TabStore,
  query = "",
): Promise<void> {
  dlog(`[fetch] start addr=${addr.slice(0, 8)}…`);
  try {
    const r = await invoke<Rendition>("fetch_and_render", { addr, tabId: id });
    dlog(`[fetch] done addr=${addr.slice(0, 8)}… kind=${r.kind}`);
    firstFetchSucceeded = true;
    // Stop the mascot's idle-behavior timers before the renderer
    // replaces the tab contents — otherwise blink/ear-flick timers
    // keep firing on a detached element.
    findMascotIn(root)?.dispose();
    renderRendition(r, root, addr, query);
    store.setRendered(id, r);
  } catch (e) {
    const msg = errorMessage(e);
    dlog(`[fetch] fail addr=${addr.slice(0, 8)}… msg=${msg}`);
    findMascotIn(root)?.dispose();
    root.replaceChildren(buildErrorState(msg));
    store.setError(id, msg);
  }
}

function buildStageRoot(stage: HTMLElement): HTMLElement {
  const root = document.createElement("section");
  root.className = "tab-content";
  root.setAttribute("role", "tabpanel");
  stage.appendChild(root);
  return root;
}

function buildErrorState(msg: string): HTMLElement {
  const wrap = document.createElement("div");
  wrap.className = "tab-error";
  const card = document.createElement("div");
  card.className = "tab-error-card";
  const heading = document.createElement("p");
  heading.className = "tab-error-heading";
  heading.textContent = "fetch failed";
  const detail = document.createElement("p");
  detail.className = "tab-error-detail";
  detail.textContent = msg;
  card.append(heading, detail);
  wrap.appendChild(card);
  return wrap;
}

function statusFor(active: ReturnType<TabStore["active"]>): string {
  if (!active) return "";
  if (active.status === "loading") {
    return firstFetchSucceeded
      ? "fetching…"
      : "fetching… (the first connection takes a moment)";
  }
  if (active.status === "error") return `fetch failed: ${active.error ?? "(unknown)"}`;
  return "";
}

function errorMessage(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return String(e);
}

function need<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing #${id}`);
  return el as T;
}
