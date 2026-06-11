// Settings → Advanced → "Offline share card" panel.
//
// The v2 extended share card (a large, self-contained URI carrying the
// agent's ML-KEM / ML-DSA keys) is the offline / fallback pairing path:
// it works without a reachable relay, but it is too big to scan as a QR
// and never updates if the agent moves relays. The primary pairing
// surface is the QR-sized pointer URI (Share my card in the chat
// header); this panel keeps the v2 URI available for the offline case.
//
// Kept as a sibling file rather than inlined into `settings.ts` per the
// project's one-concern-per-module rule.

import { invoke } from "@tauri-apps/api/core";

/// DOM ids the panel reads from its mount root. Centralised so the HTML
/// template in `settings.ts` and the wire-up code stay in lockstep.
export const EXTENDED_CARD_IDS = {
  generate: "extended-card-generate",
  uri: "extended-card-uri",
  copy: "extended-card-copy",
  error: "extended-card-error",
} as const;

/// Shape of the `chat_card` command result (mirrors `CardWithUri` in
/// `src-tauri/src/chat.rs`).
interface CardWithUri {
  card: { agent_id: string; display_name: string };
  uri: string;
}

/// Initialise the Offline-share-card panel under a mount root (the
/// Settings overlay). Idempotent — repeated calls on the same root
/// short-circuit so reopening Settings doesn't double-bind handlers.
export function initExtendedCardPanel(root: HTMLElement): void {
  const genBtn = root.querySelector<HTMLButtonElement>(`#${EXTENDED_CARD_IDS.generate}`);
  const uriBox = root.querySelector<HTMLTextAreaElement>(`#${EXTENDED_CARD_IDS.uri}`);
  const copyBtn = root.querySelector<HTMLButtonElement>(`#${EXTENDED_CARD_IDS.copy}`);
  const errSlot = root.querySelector<HTMLParagraphElement>(`#${EXTENDED_CARD_IDS.error}`);
  if (!genBtn || !uriBox || !copyBtn || !errSlot) {
    return;
  }
  if (genBtn.dataset.bound === "1") {
    return;
  }
  genBtn.dataset.bound = "1";

  function showError(msg: string): void {
    if (!errSlot) return;
    errSlot.textContent = msg;
    errSlot.hidden = false;
  }

  genBtn.addEventListener("click", () => {
    void (async () => {
      errSlot.hidden = true;
      errSlot.textContent = "";
      genBtn.disabled = true;
      const prev = genBtn.textContent;
      genBtn.textContent = "Generating…";
      try {
        // Empty display name: the v2 card embeds whatever the daemon
        // has on file; the display name is edited elsewhere.
        const result = await invoke<CardWithUri>("chat_card", { displayName: "" });
        uriBox.value = result.uri;
        copyBtn.disabled = false;
      } catch (err) {
        showError(err instanceof Error ? err.message : String(err));
      } finally {
        genBtn.disabled = false;
        genBtn.textContent = prev;
      }
    })();
  });

  copyBtn.addEventListener("click", () => {
    void (async () => {
      if (!uriBox.value) return;
      try {
        await navigator.clipboard.writeText(uriBox.value);
        const prev = copyBtn.textContent;
        copyBtn.textContent = "Copied";
        setTimeout(() => {
          copyBtn.textContent = prev;
        }, 1200);
      } catch {
        uriBox.select();
        document.execCommand("copy");
      }
    })();
  });
}

/// Inline HTML template the Advanced section embeds verbatim into the
/// Settings overlay. Exported so `settings.ts` interpolates it without
/// duplicating the ids.
export const EXTENDED_CARD_HTML = `
      <details class="setting-collapsible" id="extended-card-details">
        <summary>Offline share card</summary>
        <p class="setting-desc">
          A fallback link that works without a reachable relay. It is too
          large to scan as a QR and won't update if you change regions, so
          use <strong>Share my card</strong> in chat for the normal case.
        </p>
        <div class="setting-actions">
          <button type="button" class="setting-action setting-action-ghost"
                  id="${EXTENDED_CARD_IDS.generate}">Generate offline link</button>
          <button type="button" class="setting-action setting-action-ghost"
                  id="${EXTENDED_CARD_IDS.copy}" disabled>Copy</button>
        </div>
        <textarea id="${EXTENDED_CARD_IDS.uri}" class="chat-dialog__uri" rows="3"
                  readonly wrap="soft" aria-label="Offline share URI"></textarea>
        <p class="setting-error" id="${EXTENDED_CARD_IDS.error}" role="alert" hidden></p>
      </details>
`;
