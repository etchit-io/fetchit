// Settings panel — opens via the gear button or Ctrl/Cmd+,. Full-page
// form. Reads current state from Rust on open; writes through on
// every change, so there is no explicit save action.

import { invoke } from "@tauri-apps/api/core";
import { getVersion } from "@tauri-apps/api/app";
import { fmtBytes } from "./format";
import { addBookmark, listBookmarks, removeBookmark, type Bookmark } from "./bookmarks";
import { MAX_BOOKMARKS_PER_QR } from "./bookmarkShare";
import { applyTheme, loadTheme, type Theme } from "./theme/theme";
import {
  ADVERTISED_RELAYS_HTML,
  initAdvertisedRelaysPanel,
} from "./settingsAdvertisedRelays";
import { BACKUP_PANEL_HTML, initBackupPanel } from "./settingsBackup";
import { CUSTODY_PANEL_HTML, initCustodyPanel } from "./settingsCustody";
import { EXTENDED_CARD_HTML, initExtendedCardPanel } from "./settingsExtendedCard";

interface ThemeOption {
  id: Theme;
  label: string;
  description: string;
}

const THEME_OPTIONS: ThemeOption[] = [
  { id: "dark", label: "Dark", description: "Brand default — ink canvas, copper accent." },
  { id: "dim", label: "Dim", description: "Warm mid-tone for less contrast than full dark." },
  { id: "light", label: "Light", description: "Bone canvas for the brightest reading surface." },
];

export type ClearMode = "persist" | "on-close" | "on-idle";

export interface CachePolicy {
  enabled: boolean;
  mode: ClearMode;
  maxBytes: number;
}

interface CacheStats {
  policy: CachePolicy;
  sizeBytes: number;
  fileCount: number;
  path: string;
}

export interface SettingsHooks {
  onNavigate: (address: string) => void;
  onBookmarksChanged?: () => void;
  /** Fired after the user changes the idle-disconnect timeout in settings.
   *  Controller wires this to its in-memory idle tracker so the timer
   *  reflects the new value without a relaunch. */
  onIdleChanged?: (timeoutMinutes: number) => void;
  /** Fired when the user clicks the per-bookmark share button.
   *  Controller routes this to the QR-share modal so any bookmark can
   *  be shared without first opening it in a tab. */
  onShareBookmark?: (address: string, label: string) => void;
  /** Fired when the user clicks "Share all" or "Share selected" in
   *  the bookmarks panel. Controller routes this to the QR-share
   *  modal's import mode, which encodes the list as a
   *  `fetchit://import?…` URL and renders a multi-bookmark QR. */
  onShareBookmarkList?: (bookmarks: Bookmark[]) => void;
  /** Fired when the user clicks "View my profile". Controller closes
   *  settings and opens the own-profile page (isSelf:true). */
  onViewMyProfile?: () => void;
}

export interface IdlePolicy {
  timeoutMinutes: number;
}

/// Fetchit-operated relay region surfaced by the Network → "Chat relay
/// region" dropdown. The list comes from the `relay_regions` Tauri
/// command (which reads `settings::KNOWN_RELAYS`) so adding a new
/// region in Rust auto-populates the dropdown without a JS update.
export interface RelayRegion {
  tag: string;
  label: string;
  url: string;
}

const CUSTOM_RELAY_TAG = "__custom__";

const IDLE_CHOICES: { value: number; label: string }[] = [
  { value: 0, label: "Never" },
  { value: 5, label: "After 5 minutes" },
  { value: 15, label: "After 15 minutes" },
  { value: 30, label: "After 30 minutes (default)" },
  { value: 60, label: "After 1 hour" },
  { value: 240, label: "After 4 hours" },
];

export interface SettingsApi {
  open: () => Promise<void>;
  close: () => void;
  isOpen: () => boolean;
  toggle: () => Promise<void>;
  refreshBookmarks: () => Promise<void>;
}

const DEFAULT_POLICY: CachePolicy = {
  enabled: false,
  mode: "persist",
  maxBytes: 500 * 1024 * 1024,
};

export function mountSettings(host: HTMLElement, hooks: SettingsHooks): SettingsApi {
  host.replaceChildren(buildPage());

  const root = host.firstElementChild as HTMLElement;
  // Stamp the running version into the About section. Tauri exposes the value
  // declared in src-tauri/tauri.conf.json's `version` field; we render it on
  // mount so users can quote what they're on without us hard-coding the
  // string in two places (tauri.conf.json stays the single source of truth).
  void getVersion().then((v) => {
    const verEl = root.querySelector<HTMLElement>("#setting-version");
    if (verEl) verEl.textContent = v;
  });
  initAdvertisedRelaysPanel(root);
  initBackupPanel(root);
  initCustodyPanel(root);
  initExtendedCardPanel(root);
  const close = root.querySelector<HTMLButtonElement>(".settings-close");
  const enabledBox = root.querySelector<HTMLInputElement>("#cache-enabled");
  const modeSelect = root.querySelector<HTMLSelectElement>("#cache-mode");
  const maxMb = root.querySelector<HTMLInputElement>("#cache-max-mb");
  const stats = root.querySelector<HTMLElement>("#cache-stats");
  const clearBtn = root.querySelector<HTMLButtonElement>("#clear-cache");
  const peersEl = root.querySelector<HTMLElement>("#net-peers");
  const bookmarksEl = root.querySelector<HTMLElement>("#bookmarks-list");
  const shareAllBtn = root.querySelector<HTMLButtonElement>("#bookmarks-share-all");
  const shareSelectedBtn = root.querySelector<HTMLButtonElement>("#bookmarks-share-selected");
  const idleSelect = root.querySelector<HTMLSelectElement>("#idle-timeout");
  const lanDirectBox = root.querySelector<HTMLInputElement>("#lan-direct-enabled");
  const relaySelect = root.querySelector<HTMLSelectElement>("#relay-region");
  const relayDesc = root.querySelector<HTMLElement>("#relay-region-desc");
  const relayCustomDetails = root.querySelector<HTMLDetailsElement>("#relay-custom-details");
  const relayCustomInput = root.querySelector<HTMLInputElement>("#relay-custom-url");
  const relayCustomSaveBtn = root.querySelector<HTMLButtonElement>("#relay-custom-save");
  const relayCustomError = root.querySelector<HTMLElement>("#relay-custom-error");

  if (
    !close ||
    !enabledBox ||
    !modeSelect ||
    !maxMb ||
    !stats ||
    !clearBtn ||
    !peersEl ||
    !bookmarksEl ||
    !shareAllBtn ||
    !shareSelectedBtn ||
    !idleSelect ||
    !lanDirectBox ||
    !relaySelect ||
    !relayDesc ||
    !relayCustomDetails ||
    !relayCustomInput ||
    !relayCustomSaveBtn ||
    !relayCustomError
  ) {
    throw new Error("settings: missing form element");
  }

  for (const choice of IDLE_CHOICES) {
    const opt = document.createElement("option");
    opt.value = String(choice.value);
    opt.textContent = choice.label;
    idleSelect.appendChild(opt);
  }

  mountAppearance(root);
  mountPeers(root);
  mountSupport(root);

  idleSelect.addEventListener("change", () => {
    const minutes = Math.max(0, Number(idleSelect.value) || 0);
    void invoke("set_idle_policy", { policy: { timeoutMinutes: minutes } })
      .then(() => hooks.onIdleChanged?.(minutes))
      .catch(() => {});
  });

  lanDirectBox.addEventListener("change", () => {
    const enabled = lanDirectBox.checked;
    void invoke("set_lan_direct_enabled", { enabled }).catch(() => {
      // Roll the checkbox back on failure so the UI matches truth.
      lanDirectBox.checked = !enabled;
    });
  });

  // Region picker state — KNOWN_RELAYS comes from Rust (see
  // `settings::KNOWN_RELAYS`) so a new region added there shows up in
  // the dropdown on the next render with no JS change.
  let relayRegions: RelayRegion[] = [];
  let lastRelayUrl = "";

  const renderRelayChoice = (
    url: string,
    regions: RelayRegion[],
  ): void => {
    const known = regions.find((r) => r.url === url);
    if (known) {
      relaySelect.value = known.tag;
      relayDesc.textContent = `Chat routes through ${known.url}.`;
      relayCustomDetails.open = false;
    } else {
      relaySelect.value = CUSTOM_RELAY_TAG;
      relayDesc.textContent = `Custom relay: ${url}`;
      relayCustomInput.value = url;
      relayCustomDetails.open = true;
    }
  };

  const applyRelay = async (url: string): Promise<void> => {
    try {
      await invoke("set_relay_url", { url });
      lastRelayUrl = url;
      relayCustomError.hidden = true;
      relayCustomError.textContent = "";
      renderRelayChoice(url, relayRegions);
    } catch (e) {
      relayCustomError.textContent = String(e);
      relayCustomError.hidden = false;
      // Revert dropdown to whatever the daemon currently knows about.
      renderRelayChoice(lastRelayUrl, relayRegions);
    }
  };

  relaySelect.addEventListener("change", () => {
    const tag = relaySelect.value;
    if (tag === CUSTOM_RELAY_TAG) {
      relayCustomDetails.open = true;
      relayCustomInput.focus();
      // Snap back the dropdown so it doesn't claim "Custom" until the
      // user actually saves a URL.
      renderRelayChoice(lastRelayUrl, relayRegions);
      return;
    }
    const picked = relayRegions.find((r) => r.tag === tag);
    if (!picked) return;
    void applyRelay(picked.url);
  });

  relayCustomSaveBtn.addEventListener("click", () => {
    const url = relayCustomInput.value.trim();
    if (!url) {
      relayCustomError.textContent = "Enter a URL first.";
      relayCustomError.hidden = false;
      return;
    }
    void applyRelay(url);
  });

  const refreshIdle = async (): Promise<void> => {
    try {
      const p = await invoke<IdlePolicy>("idle_policy");
      idleSelect!.value = String(p.timeoutMinutes);
    } catch {
      idleSelect!.value = "30";
    }
  };

  const refreshLanDirect = async (): Promise<void> => {
    try {
      const on = await invoke<boolean>("lan_direct_enabled");
      lanDirectBox!.checked = !!on;
    } catch {
      lanDirectBox!.checked = false;
    }
  };

  const refreshRelay = async (): Promise<void> => {
    // Disable the dropdown until we've heard from the backend so a
    // pre-refresh click can't fire `applyRelay` against the empty
    // initial `lastRelayUrl` (which would flip the UI to "Custom" with
    // a blank URL on the revert path).
    relaySelect!.disabled = true;
    relayCustomSaveBtn!.disabled = true;
    try {
      const [regions, url] = await Promise.all([
        invoke<RelayRegion[]>("relay_regions"),
        invoke<string>("relay_url"),
      ]);
      relayRegions = regions;
      lastRelayUrl = url;
      relaySelect!.replaceChildren();
      for (const r of regions) {
        const opt = document.createElement("option");
        opt.value = r.tag;
        opt.textContent = r.label;
        relaySelect!.appendChild(opt);
      }
      const custom = document.createElement("option");
      custom.value = CUSTOM_RELAY_TAG;
      custom.textContent = "Custom…";
      relaySelect!.appendChild(custom);
      renderRelayChoice(url, regions);
    } catch {
      // Backend unavailable — leave the dropdown empty and the desc
      // line blank rather than rendering misleading state.
      relaySelect!.replaceChildren();
      relayDesc!.textContent = "";
    } finally {
      relaySelect!.disabled = false;
      relayCustomSaveBtn!.disabled = false;
    }
  };

  // Peer-count polling — only runs while the panel is open so we don't burn
  // IPC every 5 seconds in the background.
  let peersTimer: number | null = null;
  const refreshPeers = async (): Promise<void> => {
    try {
      const n = await invoke<number>("peer_count");
      peersEl!.textContent = String(n);
      peersEl!.dataset.state = n > 0 ? "on" : "off";
    } catch {
      peersEl!.textContent = "—";
      peersEl!.dataset.state = "off";
    }
  };

  // Bookmark-list share selection. Persists across `refreshBookmarks`
  // calls so renames / deletes don't drop the user's in-progress
  // selection. Pruned to only-still-present addresses on every
  // refresh.
  const selectedAddresses = new Set<string>();
  let currentBookmarks: Bookmark[] = [];

  const shareSelection = (bookmarks: Bookmark[]): void => {
    if (bookmarks.length === 0) return;
    const capped = bookmarks.slice(0, MAX_BOOKMARKS_PER_QR);
    hooks.onShareBookmarkList?.(capped);
  };

  const updateShareButtons = (): void => {
    const total = currentBookmarks.length;
    const selected = selectedAddresses.size;
    shareAllBtn!.disabled = total === 0;
    shareAllBtn!.textContent =
      total > MAX_BOOKMARKS_PER_QR
        ? `Share first ${MAX_BOOKMARKS_PER_QR} (of ${total})`
        : "Share all";
    shareSelectedBtn!.disabled = selected === 0;
    shareSelectedBtn!.textContent = `Share ${selected} selected`;
  };

  shareAllBtn.addEventListener("click", () => shareSelection(currentBookmarks));
  shareSelectedBtn.addEventListener("click", () => {
    const picked = currentBookmarks.filter((bm) => selectedAddresses.has(bm.address));
    shareSelection(picked);
  });

  const onRowToggle = (address: string, checked: boolean): void => {
    if (checked) selectedAddresses.add(address);
    else selectedAddresses.delete(address);
    updateShareButtons();
  };

  const refreshBookmarks = async (): Promise<void> => {
    let list: Bookmark[] = [];
    try {
      list = await listBookmarks();
    } catch {
      // leave empty
    }
    // Newest first — stable on rename because we keep the original createdAt.
    list.sort((a, b) => b.createdAt - a.createdAt);
    currentBookmarks = list;
    // Drop selections whose address vanished (deleted from another window etc.).
    for (const addr of [...selectedAddresses]) {
      if (!list.some((bm) => bm.address === addr)) selectedAddresses.delete(addr);
    }
    bookmarksEl!.replaceChildren();
    if (list.length === 0) {
      const empty = document.createElement("div");
      empty.className = "bookmark-empty";
      empty.textContent = "No bookmarks yet — click the ★ in the toolbar to save an address.";
      bookmarksEl!.appendChild(empty);
      updateShareButtons();
      return;
    }
    for (const bm of list) {
      bookmarksEl!.appendChild(
        buildBookmarkRow(bm, hooks, refreshBookmarks, {
          selected: selectedAddresses.has(bm.address),
          onToggle: onRowToggle,
        }),
      );
    }
    updateShareButtons();
  };

  const api: SettingsApi = {
    open: async () => {
      host.hidden = false;
      document.body.dataset.view = "settings";
      await Promise.all([
        refresh(),
        refreshPeers(),
        refreshBookmarks(),
        refreshIdle(),
        refreshLanDirect(),
        refreshRelay(),
      ]);
      if (peersTimer === null) {
        peersTimer = window.setInterval(() => void refreshPeers(), 5_000);
      }
    },
    close: () => {
      host.hidden = true;
      delete document.body.dataset.view;
      if (peersTimer !== null) {
        window.clearInterval(peersTimer);
        peersTimer = null;
      }
    },
    isOpen: () => !host.hidden,
    toggle: async () => {
      if (api.isOpen()) api.close();
      else await api.open();
    },
    refreshBookmarks,
  };

  let suspendApply = false;
  const applyPolicy = (next: CachePolicy): void => {
    if (suspendApply) return;
    void invoke("set_cache_policy", { policy: next })
      .then(() => refresh())
      .catch(() => refresh());
  };

  close.addEventListener("click", () => api.close());

  const viewMyProfileBtn = root.querySelector<HTMLButtonElement>("[data-act=view-my-profile]");
  viewMyProfileBtn?.addEventListener("click", () => hooks.onViewMyProfile?.());

  enabledBox.addEventListener("change", () => {
    applyPolicy(readPolicy({ enabledBox, modeSelect, maxMb }));
  });
  modeSelect.addEventListener("change", () => {
    applyPolicy(readPolicy({ enabledBox, modeSelect, maxMb }));
  });
  maxMb.addEventListener("change", () => {
    applyPolicy(readPolicy({ enabledBox, modeSelect, maxMb }));
  });

  clearBtn.addEventListener("click", () => {
    void invoke("clear_cache").then(() => refresh()).catch(() => refresh());
  });

  async function refresh(): Promise<void> {
    let snap: CacheStats | null = null;
    try {
      snap = await invoke<CacheStats>("cache_stats");
    } catch {
      snap = { policy: DEFAULT_POLICY, sizeBytes: 0, fileCount: 0, path: "(unavailable)" };
    }
    suspendApply = true;
    try {
      enabledBox!.checked = snap.policy.enabled;
      modeSelect!.value = snap.policy.mode;
      maxMb!.value = String(Math.max(1, Math.round(snap.policy.maxBytes / (1024 * 1024))));
      stats!.replaceChildren();
      const sizeLine = document.createElement("div");
      sizeLine.textContent = `Currently using ${fmtBytes(snap.sizeBytes)} across ${snap.fileCount} file${snap.fileCount === 1 ? "" : "s"}.`;
      const pathLine = document.createElement("div");
      const pathLabel = document.createTextNode("Path: ");
      const pathCode = document.createElement("code");
      pathCode.textContent = snap.path;
      pathLine.append(pathLabel, pathCode);
      stats!.append(sizeLine, pathLine);
      clearBtn!.disabled = snap.fileCount === 0;
    } finally {
      suspendApply = false;
    }
  }

  return api;
}

function readPolicy(els: {
  enabledBox: HTMLInputElement;
  modeSelect: HTMLSelectElement;
  maxMb: HTMLInputElement;
}): CachePolicy {
  const mb = Math.max(1, Math.floor(Number(els.maxMb.value) || 0));
  return {
    enabled: els.enabledBox.checked,
    mode: (els.modeSelect.value as ClearMode) ?? "persist",
    maxBytes: mb * 1024 * 1024,
  };
}

function mountAppearance(root: HTMLElement): void {
  const optionsHost = root.querySelector(".settings-theme-options");
  if (!optionsHost) return;
  const current = loadTheme();
  for (const opt of THEME_OPTIONS) {
    const label = document.createElement("label");
    label.className = "settings-theme-option";
    label.dataset.theme = opt.id;

    const input = document.createElement("input");
    input.type = "radio";
    input.name = "theme";
    input.value = opt.id;
    input.checked = opt.id === current;
    input.addEventListener("change", () => {
      if (input.checked) applyTheme(opt.id);
    });

    const text = document.createElement("span");
    text.className = "settings-theme-text";
    const lbl = document.createElement("span");
    lbl.className = "settings-theme-label";
    lbl.textContent = opt.label;
    const desc = document.createElement("span");
    desc.className = "settings-theme-desc";
    desc.textContent = opt.description;
    text.append(lbl, desc);

    label.append(input, text);
    optionsHost.appendChild(label);
  }
}

interface PeersRefreshResult {
  peers: string[];
  updated: boolean;
}

function mountPeers(root: HTMLElement): void {
  const editor = root.querySelector<HTMLTextAreaElement>("#peers-editor");
  const errorEl = root.querySelector<HTMLElement>("#peers-error");
  const saveBtn = root.querySelector<HTMLButtonElement>("#peers-save");
  const resetBtn = root.querySelector<HTMLButtonElement>("#peers-reset");
  const refreshBtn = root.querySelector<HTMLButtonElement>("#peers-refresh");
  if (!editor || !errorEl || !saveBtn || !resetBtn || !refreshBtn) return;

  const showError = (msg: string): void => {
    errorEl.textContent = msg;
    errorEl.hidden = false;
  };
  const clearError = (): void => {
    errorEl.textContent = "";
    errorEl.hidden = true;
  };

  // Prefill: user override if set, otherwise the bundled defaults so the
  // user can see what they're replacing rather than starting blank.
  const prefill = async (): Promise<void> => {
    try {
      const overrideList = await invoke<string[]>("peers_override");
      if (overrideList.length > 0) {
        editor.value = overrideList.join("\n");
        return;
      }
      const defaults = await invoke<string[]>("default_peers");
      editor.value = defaults.join("\n");
    } catch {
      editor.value = "";
    }
  };
  void prefill();

  editor.addEventListener("input", clearError);

  saveBtn.addEventListener("click", () => {
    clearError();
    const peers = editor.value.split("\n").map((s) => s.trim()).filter((s) => s.length > 0);
    if (peers.length === 0) {
      showError("at least one peer is required (or use Reset)");
      return;
    }
    saveBtn.disabled = true;
    void invoke<string[]>("set_peers_override", { peers })
      .then((cleaned) => {
        editor.value = cleaned.join("\n");
      })
      .catch((e: unknown) => showError(typeof e === "string" ? e : "save failed"))
      .finally(() => {
        saveBtn.disabled = false;
      });
  });

  resetBtn.addEventListener("click", () => {
    clearError();
    resetBtn.disabled = true;
    void invoke("reset_peers_override")
      .then(() => prefill())
      .catch((e: unknown) => showError(typeof e === "string" ? e : "reset failed"))
      .finally(() => {
        resetBtn.disabled = false;
      });
  });

  refreshBtn.addEventListener("click", () => {
    clearError();
    refreshBtn.disabled = true;
    void invoke<PeersRefreshResult>("refresh_peers_from_upstream")
      .then((result) => {
        editor.value = result.peers.join("\n");
        // showError is the only status surface in this UI; reused
        // here for success notes too.
        const n = result.peers.length;
        const verb = result.updated ? "Updated" : "Already current";
        showError(`${verb} · ${n} peer${n === 1 ? "" : "s"}`);
      })
      .catch((e: unknown) => showError(typeof e === "string" ? e : "refresh failed"))
      .finally(() => {
        refreshBtn.disabled = false;
      });
  });
}

function mountSupport(root: HTMLElement): void {
  const addrEl = root.querySelector<HTMLElement>(".setting-support-addr");
  const copyBtn = root.querySelector<HTMLButtonElement>(".setting-support-copy");
  const status = root.querySelector<HTMLElement>(".setting-support-status");
  if (!addrEl || !copyBtn || !status) return;
  const address = addrEl.textContent?.trim() ?? "";
  copyBtn.addEventListener("click", () => {
    void (async () => {
      try {
        await navigator.clipboard.writeText(address);
        status.textContent = "Address copied.";
        status.dataset.tone = "ok";
      } catch {
        status.textContent = "Copy failed.";
        status.dataset.tone = "error";
      }
    })();
  });
}

function buildPage(): HTMLElement {
  const page = document.createElement("div");
  page.className = "settings-page";
  page.innerHTML = `
    <header class="settings-head">
      <h1>Settings</h1>
      <button type="button" class="settings-close" aria-label="Close settings">×</button>
    </header>
    <section class="setting-group" id="group-appearance">
      <details class="setting-collapsible">
        <summary><h2>Appearance</h2></summary>
        <p class="setting-desc">
          fetch<span class="brand-mark">&gt;</span>it ships dark — pick a softer surface if dark isn&rsquo;t your thing.
        </p>
        <div class="settings-theme-options" role="radiogroup" aria-label="Theme"></div>
      </details>
    </section>
    <section class="setting-group" id="group-network">
      <h2>Network</h2>
      <div class="setting-row">
        <span>Connected peers</span>
        <span id="net-peers" data-state="off">—</span>
      </div>
      <label class="setting-row">
        <span>Chat relay region</span>
        <select id="relay-region"></select>
      </label>
      <p class="setting-desc" id="relay-region-desc"></p>
      <p class="setting-desc">Moving relays republishes your reachability record; your contacts update automatically.</p>
      <details class="setting-collapsible" id="relay-custom-details">
        <summary>Use a custom relay</summary>
        <p class="setting-desc">
          Point chat at your own relay. The URL must be the base (no path), e.g.
          <code>http://relay.example:8088</code>.
        </p>
        <div class="setting-row setting-row--stack">
          <input type="text" id="relay-custom-url" spellcheck="false"
                 placeholder="http://relay.example:8088"
                 aria-label="Custom relay URL">
          <button type="button" class="setting-action" id="relay-custom-save">Use this relay</button>
        </div>
        <p class="setting-error" id="relay-custom-error" role="alert" hidden></p>
      </details>
      <label class="setting-row">
        <span>Disconnect when idle</span>
        <select id="idle-timeout"></select>
      </label>
<label class="setting-row">
        <span>Enable LAN delivery <em class="setting-pill">experimental</em></span>
        <input type="checkbox" id="lan-direct-enabled">
      </label>
      <p class="setting-desc">
        Send chat directly between devices on the same network. Falls back to relay automatically.
      </p>
      ${ADVERTISED_RELAYS_HTML}
    </section>
    <section class="setting-group" id="group-backup">
      <h2>Identity backup</h2>
      ${BACKUP_PANEL_HTML}
    </section>
    <section class="setting-group" id="group-advanced">
      <h2>Advanced</h2>
      <div class="setting-row">
        <span>Your profile</span>
        <button type="button" class="setting-action setting-action-ghost" data-act="view-my-profile">View my profile</button>
      </div>
      ${CUSTODY_PANEL_HTML}
      ${EXTENDED_CARD_HTML}
    </section>
    <section class="setting-group" id="group-peers">
      <details class="setting-collapsible">
        <summary><h2>Bootstrap peers</h2></summary>
        <textarea id="peers-editor" rows="6" spellcheck="false" aria-label="Bootstrap peers"></textarea>
        <p class="setting-error" id="peers-error" role="alert" hidden></p>
        <div class="setting-actions">
          <button type="button" class="setting-action" id="peers-save">Save</button>
          <button type="button" class="setting-action setting-action-ghost" id="peers-reset">Reset to defaults</button>
          <button type="button" class="setting-action setting-action-ghost" id="peers-refresh">Refresh from upstream</button>
        </div>
      </details>
    </section>
    <section class="setting-group" id="group-cache">
      <h2>On-disk byte cache</h2>
      <p class="setting-desc">
        Off by default. When on, fetched bytes stay on disk for instant re-open.
      </p>
      <label class="setting-row">
        <span>Enable on-disk cache</span>
        <input type="checkbox" id="cache-enabled">
      </label>
      <label class="setting-row">
        <span>When to clear</span>
        <select id="cache-mode">
          <option value="persist">Persist across sessions</option>
          <option value="on-close">Clear when the app closes</option>
          <option value="on-idle">Clear after idle disconnect</option>
        </select>
      </label>
      <label class="setting-row">
        <span>Maximum size (MB)</span>
        <input type="number" id="cache-max-mb" min="1" step="1" value="500">
      </label>
      <div class="setting-stats" id="cache-stats" aria-live="polite"></div>
      <button type="button" class="setting-action" id="clear-cache">Clear cache now</button>
    </section>
    <section class="setting-group" id="group-bookmarks">
      <h2>Bookmarks</h2>
      <div class="bookmark-toolbar">
        <button type="button" class="setting-action setting-action-ghost" id="bookmarks-share-all">Share all</button>
        <button type="button" class="setting-action setting-action-ghost" id="bookmarks-share-selected" disabled>Share 0 selected</button>
      </div>
      <div id="bookmarks-list"></div>
    </section>
    <section class="setting-group" id="group-support">
      <details class="setting-collapsible">
        <summary><h2>Support development</h2></summary>
        <div class="setting-support-row">
          <code class="setting-support-addr">0xC842451eC3454913585B885240e58aa5E4F4ed2b</code>
          <button type="button" class="setting-action setting-action-ghost setting-support-copy">Copy address</button>
        </div>
        <p class="setting-support-status" role="status" aria-live="polite"></p>
      </details>
    </section>
    <section class="setting-group setting-group-about" id="group-about">
      <details class="setting-collapsible">
        <summary><h2>About &amp; License</h2></summary>
        <p class="setting-desc">
          Version <code id="setting-version">&hellip;</code>
        </p>
        <p class="setting-desc">
          <strong>fetch<span class="brand-mark">&gt;</span>it &mdash; beta software.</strong>
          <a href="https://www.gnu.org/licenses/agpl-3.0.html" target="_blank" rel="noopener noreferrer">AGPL-3.0-only</a>
          or commercial (<code>COMMERCIAL.md</code>). Provided <em>"AS IS"</em>, no warranty.
        </p>
      </details>
    </section>
  `;
  return page;
}

interface RowSelection {
  selected: boolean;
  onToggle: (address: string, checked: boolean) => void;
}

function buildBookmarkRow(
  bm: Bookmark,
  hooks: SettingsHooks,
  reload: () => Promise<void>,
  selection: RowSelection,
): HTMLElement {
  const row = document.createElement("div");
  row.className = "bookmark-row";

  const select = document.createElement("input");
  select.type = "checkbox";
  select.className = "bookmark-select";
  select.checked = selection.selected;
  select.setAttribute("aria-label", `Select ${bm.label} for bulk share`);
  select.addEventListener("click", (e) => e.stopPropagation());
  select.addEventListener("change", () => {
    selection.onToggle(bm.address, select.checked);
  });

  const main = document.createElement("button");
  main.type = "button";
  main.className = "bookmark-main";
  main.title = "Open this address";

  const label = document.createElement("span");
  label.className = "bookmark-label";
  label.textContent = bm.label;
  // Stops the row click from firing when the user clicks the label to rename.
  label.addEventListener("click", (e) => {
    e.stopPropagation();
    beginRename(label, bm, reload);
  });

  const addr = document.createElement("span");
  addr.className = "bookmark-addr";
  addr.textContent = `${bm.address.slice(0, 12)}…${bm.address.slice(-6)}`;

  main.append(label, addr);
  main.addEventListener("click", () => hooks.onNavigate(bm.address));

  const share = document.createElement("button");
  share.type = "button";
  share.className = "bookmark-share";
  share.setAttribute("aria-label", `Share ${bm.label}`);
  share.title = "Share QR";
  share.textContent = "▦";
  share.addEventListener("click", (e) => {
    e.stopPropagation();
    hooks.onShareBookmark?.(bm.address, bm.label);
  });

  const del = document.createElement("button");
  del.type = "button";
  del.className = "bookmark-delete";
  del.setAttribute("aria-label", `Remove bookmark for ${bm.label}`);
  del.title = "Remove bookmark";
  del.textContent = "×";
  del.addEventListener("click", (e) => {
    e.stopPropagation();
    void removeBookmark(bm.address).then(() => {
      hooks.onBookmarksChanged?.();
      return reload();
    }).catch(() => {});
  });

  row.append(select, main, share, del);
  return row;
}

function beginRename(
  label: HTMLElement,
  bm: Bookmark,
  reload: () => Promise<void>,
): void {
  const input = document.createElement("input");
  input.type = "text";
  input.className = "bookmark-rename";
  input.value = bm.label;
  input.maxLength = 200;
  const commit = (): void => {
    const next = input.value.trim();
    const restore = (text: string): void => {
      const span = document.createElement("span");
      span.className = "bookmark-label";
      span.textContent = text;
      span.addEventListener("click", (e) => {
        e.stopPropagation();
        beginRename(span, { ...bm, label: text }, reload);
      });
      input.replaceWith(span);
    };
    if (!next || next === bm.label) {
      restore(bm.label);
      return;
    }
    void addBookmark(bm.address, next).then(() => reload()).catch(() => restore(bm.label));
  };
  input.addEventListener("blur", commit);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      input.blur();
    } else if (e.key === "Escape") {
      input.value = bm.label;
      input.blur();
    }
  });
  // Clicks inside the input must not bubble to the row's navigate handler.
  input.addEventListener("click", (e) => e.stopPropagation());
  label.replaceWith(input);
  input.focus();
  input.select();
}
