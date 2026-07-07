// M3 Phase E3 — Settings → Network → "Advertised relays" panel.
//
// Drives the editable list of relays the local agent publishes in its
// v2 contact card's `fetchit_rendezvous_hints` slot. The Save button
// calls `chat_regenerate_card_with_relays` on the Rust side; the
// underlying validator (`RendezvousHintsV1::from_value`) rejects
// empty / non-`wss://` / oversize lists with a `String` error that
// renders verbatim into the panel's error slot.
//
// Kept as a sibling file rather than inlined into `settings.ts` per
// the project's one-concern-per-module rule.

import { invoke } from "@tauri-apps/api/core";

/// DOM ids the panel reads from its mount root. Centralised so the
/// HTML template in `settings.ts` and the wire-up code stay in lockstep.
export const ADVERTISED_RELAYS_IDS = {
  list: "advertised-relays-list",
  add: "advertised-relays-add",
  save: "advertised-relays-save",
  error: "advertised-relays-error",
  status: "advertised-relays-status",
} as const;

/// Initialise the Advertised-relays panel under a mount root (the
/// Settings overlay). Idempotent — repeated calls on the same root
/// short-circuit so reopening Settings doesn't double-bind handlers.
export function initAdvertisedRelaysPanel(root: HTMLElement): void {
  const list = root.querySelector<HTMLDivElement>(`#${ADVERTISED_RELAYS_IDS.list}`);
  const addBtn = root.querySelector<HTMLButtonElement>(`#${ADVERTISED_RELAYS_IDS.add}`);
  const saveBtn = root.querySelector<HTMLButtonElement>(`#${ADVERTISED_RELAYS_IDS.save}`);
  const errSlot = root.querySelector<HTMLParagraphElement>(`#${ADVERTISED_RELAYS_IDS.error}`);
  const statusSlot = root.querySelector<HTMLParagraphElement>(
    `#${ADVERTISED_RELAYS_IDS.status}`,
  );
  if (!list || !addBtn || !saveBtn || !errSlot || !statusSlot) {
    return;
  }
  if (list.dataset.bound === "1") {
    return;
  }
  list.dataset.bound = "1";

  function clearMessages(): void {
    if (errSlot) {
      errSlot.hidden = true;
      errSlot.textContent = "";
    }
    if (statusSlot) {
      statusSlot.hidden = true;
      statusSlot.textContent = "";
    }
  }

  function showError(msg: string): void {
    if (!errSlot) {
      return;
    }
    errSlot.textContent = msg;
    errSlot.hidden = false;
    if (statusSlot) {
      statusSlot.hidden = true;
    }
  }

  function showStatus(msg: string): void {
    if (!statusSlot) {
      return;
    }
    statusSlot.textContent = msg;
    statusSlot.hidden = false;
    if (errSlot) {
      errSlot.hidden = true;
    }
  }

  function appendRow(initial = ""): HTMLInputElement {
    const row = document.createElement("div");
    row.className = "setting-row setting-row--stack advertised-relays-row";
    const input = document.createElement("input");
    input.type = "text";
    input.spellcheck = false;
    input.placeholder = "wss://relay.example/v1/ws";
    input.value = initial;
    input.setAttribute("aria-label", "Relay URL");
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "setting-action setting-action-ghost";
    remove.textContent = "Remove";
    remove.addEventListener("click", () => {
      row.remove();
    });
    row.append(input, remove);
    list!.append(row);
    return input;
  }

  addBtn.addEventListener("click", () => {
    clearMessages();
    const fresh = appendRow();
    fresh.focus();
  });

  saveBtn.addEventListener("click", () => {
    void saveCurrent();
  });

  async function saveCurrent(): Promise<void> {
    clearMessages();
    const relays = Array.from(list!.querySelectorAll<HTMLInputElement>("input"))
      .map((el) => el.value.trim())
      .filter((v) => v.length > 0);
    try {
      await invoke("chat_regenerate_card_with_relays", { relays });
      showStatus(`Saved ${relays.length} relay${relays.length === 1 ? "" : "s"}.`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      showError(msg);
    }
  }
}

/// Inline HTML template the Network section embeds verbatim into the
/// Settings overlay. Exported so `settings.ts` interpolates it into
/// its larger template without duplicating the ids.
export const ADVERTISED_RELAYS_HTML = `
  <details class="setting-collapsible" id="advertised-relays-details">
    <summary>Advertise relays in my contact card</summary>
    <p class="setting-desc">
      Contacts dial you through these relays. The list is published in your
      contact card, so anyone you share it with sees which relays you use;
      a relay that is down or wrong makes you unreachable until contacts
      receive your next card. <code>wss://</code> only.
    </p>
    <div id="${ADVERTISED_RELAYS_IDS.list}"></div>
    <div class="setting-actions">
      <button type="button" class="setting-action setting-action-ghost"
              id="${ADVERTISED_RELAYS_IDS.add}">+ Add relay</button>
      <button type="button" class="setting-action"
              id="${ADVERTISED_RELAYS_IDS.save}">Save</button>
    </div>
    <p class="setting-error" id="${ADVERTISED_RELAYS_IDS.error}" role="alert" hidden></p>
    <p class="setting-desc" id="${ADVERTISED_RELAYS_IDS.status}" role="status" aria-live="polite" hidden></p>
  </details>
`;
