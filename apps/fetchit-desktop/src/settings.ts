// Settings panel — opens via the gear button or Ctrl/Cmd+,. Browser-familiar
// full-page form (Chrome / Firefox / Brave all do the same). Reads current
// state from Rust on open; writes through on every change so the disk reflects
// the user's choice without a "Save" button.

import { invoke } from "@tauri-apps/api/core";
import { fmtBytes } from "./format";
import { addBookmark, listBookmarks, removeBookmark, type Bookmark } from "./bookmarks";
import { applyTheme, loadTheme, type Theme } from "./theme/theme";

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
}

export interface IdlePolicy {
  timeoutMinutes: number;
}

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
  const close = root.querySelector<HTMLButtonElement>(".settings-close");
  const enabledBox = root.querySelector<HTMLInputElement>("#cache-enabled");
  const modeSelect = root.querySelector<HTMLSelectElement>("#cache-mode");
  const maxMb = root.querySelector<HTMLInputElement>("#cache-max-mb");
  const stats = root.querySelector<HTMLElement>("#cache-stats");
  const clearBtn = root.querySelector<HTMLButtonElement>("#clear-cache");
  const peersEl = root.querySelector<HTMLElement>("#net-peers");
  const bookmarksEl = root.querySelector<HTMLElement>("#bookmarks-list");
  const idleSelect = root.querySelector<HTMLSelectElement>("#idle-timeout");

  if (
    !close ||
    !enabledBox ||
    !modeSelect ||
    !maxMb ||
    !stats ||
    !clearBtn ||
    !peersEl ||
    !bookmarksEl ||
    !idleSelect
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

  idleSelect.addEventListener("change", () => {
    const minutes = Math.max(0, Number(idleSelect.value) || 0);
    void invoke("set_idle_policy", { policy: { timeoutMinutes: minutes } })
      .then(() => hooks.onIdleChanged?.(minutes))
      .catch(() => {});
  });

  const refreshIdle = async (): Promise<void> => {
    try {
      const p = await invoke<IdlePolicy>("idle_policy");
      idleSelect!.value = String(p.timeoutMinutes);
    } catch {
      idleSelect!.value = "30";
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

  const refreshBookmarks = async (): Promise<void> => {
    let list: Bookmark[] = [];
    try {
      list = await listBookmarks();
    } catch {
      // leave empty
    }
    bookmarksEl!.replaceChildren();
    if (list.length === 0) {
      const empty = document.createElement("div");
      empty.className = "bookmark-empty";
      empty.textContent = "No bookmarks yet — click the ★ in the toolbar to save an address.";
      bookmarksEl!.appendChild(empty);
      return;
    }
    // Newest first — stable on rename because we keep the original createdAt.
    list.sort((a, b) => b.createdAt - a.createdAt);
    for (const bm of list) bookmarksEl!.appendChild(buildBookmarkRow(bm, hooks, refreshBookmarks));
  };

  const api: SettingsApi = {
    open: async () => {
      host.hidden = false;
      document.body.dataset.view = "settings";
      await Promise.all([refresh(), refreshPeers(), refreshBookmarks(), refreshIdle()]);
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

function mountPeers(root: HTMLElement): void {
  const editor = root.querySelector<HTMLTextAreaElement>("#peers-editor");
  const errorEl = root.querySelector<HTMLElement>("#peers-error");
  const saveBtn = root.querySelector<HTMLButtonElement>("#peers-save");
  const resetBtn = root.querySelector<HTMLButtonElement>("#peers-reset");
  if (!editor || !errorEl || !saveBtn || !resetBtn) return;

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
      <p class="setting-desc">
        fetch<span class="brand-mark">&gt;</span>it connects to the Autonomi network lazily — the first fetch kicks off the
        client. While this panel is open, peer count auto-refreshes every 5 seconds.
      </p>
      <div class="setting-row">
        <span>Connected peers</span>
        <span id="net-peers" data-state="off">—</span>
      </div>
      <label class="setting-row">
        <span>Disconnect when idle</span>
        <select id="idle-timeout"></select>
      </label>
      <p class="setting-desc setting-desc-muted">
        After this many minutes with no mouse / keyboard activity, fetch<span class="brand-mark">&gt;</span>it
        drops the network connection and clears the in-memory cache. If the
        on-disk cache mode below is set to <em>Clear after idle</em>, that
        gets wiped too.
      </p>
    </section>
    <section class="setting-group" id="group-peers">
      <details class="setting-collapsible">
        <summary><h2>Bootstrap peers</h2></summary>
        <p class="setting-desc">
          The list of Autonomi peers fetch<span class="brand-mark">&gt;</span>it dials on the first fetch.
          Defaults to the bundled production list; override only if you
          know what you&rsquo;re doing (running a local node, joining a
          test network, etc.). One peer per line — either an
          <code>ip:port</code> shorthand or a full
          <code>/ip4/&hellip;/udp/&hellip;/quic</code> multiaddr.
        </p>
        <textarea id="peers-editor" rows="6" spellcheck="false" aria-label="Bootstrap peers"></textarea>
        <p class="setting-error" id="peers-error" role="alert" hidden></p>
        <div class="setting-actions">
          <button type="button" class="setting-action" id="peers-save">Save</button>
          <button type="button" class="setting-action setting-action-ghost" id="peers-reset">Reset to defaults</button>
        </div>
        <p class="setting-desc setting-desc-muted">
          Saving drops the current connection so the next fetch reconnects
          using the new list.
        </p>
      </details>
    </section>
    <section class="setting-group" id="group-cache">
      <h2>On-disk byte cache</h2>
      <p class="setting-desc">
        Off by default — a fresh install leaves zero on-disk trace of fetched content.
        When enabled, fetched bytes are kept locally so reopening a recent address is
        instant (and air-gap testing works). Content survives until the chosen clear
        mode wipes it, or you press <em>Clear cache now</em>.
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
      <p class="setting-desc">
        Star addresses in the toolbar to save them here. Click a row to navigate;
        click the label to rename; click × to remove.
      </p>
      <div id="bookmarks-list"></div>
    </section>
    <section class="setting-group setting-group-about" id="group-about">
      <details class="setting-collapsible">
        <summary><h2>About &amp; License</h2></summary>
        <p class="setting-desc">
          <strong>fetch<span class="brand-mark">&gt;</span>it &mdash; beta software.</strong>
          Released under the
          <a href="https://www.gnu.org/licenses/agpl-3.0.html" target="_blank" rel="noopener noreferrer">AGPL-3.0-only</a>
          license, with a commercial license available separately (see
          <code>COMMERCIAL.md</code> in the source tree). Provided
          <em>"AS IS" without warranty of any kind, express or implied</em>;
          the authors and copyright holders accept no liability for any damages arising
          from its use. See sections&nbsp;15&nbsp;&amp;&nbsp;16 of the AGPL for the full
          disclaimer.
        </p>
        <p class="setting-desc setting-desc-muted">
          Security model and threat scope: <code>docs/SECURITY.md</code> in the source tree.
        </p>
      </details>
    </section>
  `;
  return page;
}

function buildBookmarkRow(
  bm: Bookmark,
  hooks: SettingsHooks,
  reload: () => Promise<void>,
): HTMLElement {
  const row = document.createElement("div");
  row.className = "bookmark-row";

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

  row.append(main, del);
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
