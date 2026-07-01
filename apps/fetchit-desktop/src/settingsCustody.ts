// Settings > Advanced > "Chat data protection" panel.
//
// Surfaces the at-rest custody mode (OS keychain vs passphrase) and
// drives `chat_rekey_vault` to switch between them. The risk framing
// is specific: a forgotten passphrase means chat data on this device
// is unrecoverable.
//
// Kept as a sibling file rather than inlined into `settings.ts` per
// the project's one-concern-per-module rule.

import { invoke } from "@tauri-apps/api/core";

/// DOM ids the panel reads from its mount root. Centralised so the
/// HTML template and the wire-up code stay in lockstep.
export const CUSTODY_IDS = {
  status: "custody-status",
  passphrase: "custody-passphrase",
  toPassphrase: "custody-to-passphrase",
  toKeychain: "custody-to-keychain",
  error: "custody-error",
} as const;

export const CUSTODY_COPY = {
  keychain: "Chat data on this computer is protected by your system keychain.",
  passphrase: "Chat data on this computer is protected by your passphrase.",
  none: "Chat hasn't started yet. The system keychain protects it by default once it does.",
  risk:
    "If you forget the passphrase, chat data on this device can't be "
    + "recovered. Messages live only on this device either way.",
} as const;

/// Template block `settings.ts` interpolates into the Advanced group.
export const CUSTODY_PANEL_HTML = `
      <details class="setting-collapsible" id="custody-details">
        <summary>Chat data protection</summary>
        <p class="setting-desc" id="${CUSTODY_IDS.status}"></p>
        <p class="setting-desc">${CUSTODY_COPY.risk}</p>
        <div class="setting-row setting-row--stack">
          <input type="password" id="${CUSTODY_IDS.passphrase}" spellcheck="false"
                 placeholder="New passphrase"
                 aria-label="New chat passphrase">
          <button type="button" class="setting-action" id="${CUSTODY_IDS.toPassphrase}">Use a passphrase</button>
          <button type="button" class="setting-action setting-action-ghost" id="${CUSTODY_IDS.toKeychain}">Use the system keychain</button>
        </div>
        <p class="setting-error" id="${CUSTODY_IDS.error}" role="alert" hidden></p>
      </details>`;

function statusLine(mode: string): string {
  if (mode === "passphrase") return CUSTODY_COPY.passphrase;
  if (mode === "keychain") return CUSTODY_COPY.keychain;
  return CUSTODY_COPY.none;
}

/// Initialise the custody panel under a mount root (the Settings
/// overlay). Idempotent: repeated calls on the same root short-circuit
/// so reopening Settings doesn't double-bind handlers.
export function initCustodyPanel(root: HTMLElement): void {
  const status = root.querySelector<HTMLParagraphElement>(`#${CUSTODY_IDS.status}`);
  const pass = root.querySelector<HTMLInputElement>(`#${CUSTODY_IDS.passphrase}`);
  const toPass = root.querySelector<HTMLButtonElement>(`#${CUSTODY_IDS.toPassphrase}`);
  const toKey = root.querySelector<HTMLButtonElement>(`#${CUSTODY_IDS.toKeychain}`);
  const errSlot = root.querySelector<HTMLParagraphElement>(`#${CUSTODY_IDS.error}`);
  if (!status || !pass || !toPass || !toKey || !errSlot) return;
  if (status.dataset.bound === "1") return;
  status.dataset.bound = "1";

  const showError = (msg: string): void => {
    errSlot.hidden = false;
    errSlot.textContent = msg;
  };
  const clearError = (): void => {
    errSlot.hidden = true;
    errSlot.textContent = "";
  };

  const refreshStatus = async (): Promise<void> => {
    const mode = await invoke<string>("chat_custody_status").catch(() => "none");
    status.textContent = statusLine(mode);
  };
  void refreshStatus();

  const rekey = async (newPassphrase: string | null): Promise<void> => {
    clearError();
    try {
      await invoke("chat_rekey_vault", { newPassphrase });
      pass.value = "";
      await refreshStatus();
    } catch (e) {
      showError(String(e));
    }
  };

  toPass.addEventListener("click", () => {
    const value = pass.value;
    if (value.trim().length === 0) {
      showError("Enter a passphrase first.");
      return;
    }
    void rekey(value);
  });

  toKey.addEventListener("click", () => {
    void rekey(null);
  });
}
