import { invoke } from "@tauri-apps/api/core";
import type { Rendition } from "./types";
import { TabStore } from "./tabs";
import { render as renderRendition } from "./renderers/dispatch";
import { mountTabStrip } from "./ui/tabStrip";
import { mountAddressBar, type AddressBarApi } from "./ui/addressBar";
import { bindKeyboard } from "./ui/keyboard";
import { initMediaBase } from "./mediaUrl";
import { parseAutonomiUrl } from "./address";
import { mountSettings } from "./settings";
import { mountQrModal } from "./ui/qrModal";
import { mountDownloadProgress } from "./ui/downloadProgress";
import { mountAddressBarSuggestions } from "./ui/addressBarSuggestions";
import { addBookmark, deriveLabel, deriveTitle, isBookmarked, removeBookmark } from "./bookmarks";
import { getCurrent as getCurrentDeepLink, onOpenUrl } from "@tauri-apps/plugin-deep-link";
import { startIdleTracker } from "./idle";

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
  const qrHost = need<HTMLElement>("qr-modal");
  const statusEl = need<HTMLElement>("status");
  const stripEl = need<HTMLElement>("tabs");
  const stageEl = need<HTMLElement>("stage");
  const setBookmarkState = (on: boolean): void => {
    bookmarkBtn.dataset.bookmarked = on ? "true" : "false";
  };

  // Idle tracker — drops the Autonomi client + clears caches after the
  // user-configured timeout of no mouse / keyboard activity. The current
  // policy is read from settings.json; the settings panel can update it live
  // via `onIdleChanged`.
  const idle = startIdleTracker();
  void invoke<{ timeoutMinutes: number }>("idle_policy")
    .then((p) => idle.setTimeoutMinutes(p.timeoutMinutes))
    .catch(() => {});

  const settings = mountSettings(settingsHost, {
    onNavigate: (addr) => {
      settings.close();
      submit(addr, store, stageEl);
    },
    onIdleChanged: (m) => idle.setTimeoutMinutes(m),
  });
  settingsBtn.addEventListener("click", () => void settings.toggle());

  const qrModal = mountQrModal(qrHost);
  const openShare = (): void => {
    const active = store.active();
    const addr = active?.address;
    if (!addr) return;
    qrModal.open(addr, deriveTitle(active?.rendition));
  };
  shareBtn.addEventListener("click", openShare);

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
  // EPUB / PDF / lab-page exhibits etc. take over the full stage, so a
  // visible ← in the chrome is the only obvious way out for users who
  // don't know the keyboard shortcut.
  backBtn.addEventListener("click", () => backNavigate(store));

  const store = new TabStore();
  mountDownloadProgress(store);

  const bar: AddressBarApi = mountAddressBar(input, button, {
    onSubmit: (addr, query) => submit(addr, store, stageEl, query),
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
    root.appendChild(buildEmptyState());
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
  });

  let lastBookmarkAddr: string | null = null;
  store.subscribe(() => {
    const active = store.active();
    for (const t of store.list()) {
      t.root.classList.toggle("is-active", !!active && t.id === active.id);
    }
    if (!bar.isFocused()) bar.setValue(active && active.address ? active.address + active.query : "");
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
    if (existing.status === "error") startIn(existing, addr, store, query);
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
  tab.root.replaceChildren(buildSpinner());
  store.startFetch(tab.id, addr, recordHistory, query);
  void runFetch(addr, tab.id, tab.root, store, query);
}

// Session flag — true once any fetch has succeeded in this app session.
// Drives the loading-status copy: the first fetch may genuinely be slow
// (bootstrap warmup, peer connect), but every subsequent fetch in the
// same session reuses the live client. Showing "the first connection
// takes a moment" on every fetch is misleading after the first one
// lands.
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
    const r = await invoke<Rendition>("fetch_and_render", { addr });
    dlog(`[fetch] done addr=${addr.slice(0, 8)}… kind=${r.kind}`);
    firstFetchSucceeded = true;
    renderRendition(r, root, addr, query);
    store.setRendered(id, r);
  } catch (e) {
    const msg = errorMessage(e);
    dlog(`[fetch] fail addr=${addr.slice(0, 8)}… msg=${msg}`);
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

function buildEmptyState(): HTMLElement {
  const e = document.createElement("div");
  e.className = "tab-empty";
  e.textContent = "paste an address above to fetch";
  return e;
}

function buildSpinner(): HTMLElement {
  const wrap = document.createElement("div");
  wrap.className = "tab-spinner";
  wrap.setAttribute("aria-label", "loading");
  wrap.setAttribute("role", "status");
  const ring = document.createElement("div");
  ring.className = "tab-spinner-ring";
  wrap.appendChild(ring);
  return wrap;
}

function buildErrorState(msg: string): HTMLElement {
  const wrap = document.createElement("div");
  wrap.className = "tab-error";
  const heading = document.createElement("p");
  heading.className = "tab-error-heading";
  heading.textContent = "fetch failed";
  const detail = document.createElement("p");
  detail.className = "tab-error-detail";
  detail.textContent = msg;
  wrap.append(heading, detail);
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
