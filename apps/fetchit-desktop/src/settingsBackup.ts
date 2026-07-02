// Settings > "Identity backup" panel.
//
// Reveals the 24-word recovery phrase behind an explicit confirm and
// frames exactly what the words are: the account itself. Writing them
// down is the ONLY way to keep an account across a lost or replaced
// computer, so this lives as a first-class section, not under Advanced.
//
// Kept as a sibling file rather than inlined into `settings.ts` per
// the project's one-concern-per-module rule.

import { invoke } from "@tauri-apps/api/core";

/// DOM ids the panel reads from its mount root. Centralised so the
/// HTML template and the wire-up code stay in lockstep.
export const BACKUP_IDS = {
  intro: "backup-intro",
  reveal: "backup-reveal",
  words: "backup-words",
  hide: "backup-hide",
  note: "backup-note",
  error: "backup-error",
} as const;

export const BACKUP_COPY = {
  intro:
    "Your account lives in 24 words. If this computer is lost or replaced, "
    + "those words restore your whole account on a new one.",
  confirm:
    "These 24 words ARE your account — anyone who has them can become you. "
    + "Make sure nobody can see your screen, and write them on paper, "
    + "not in a file or a photo.",
  reveal: "Show my 24 words",
  confirmReveal: "I'm alone — show the words",
  hide: "Done — hide the words",
  note:
    "Write the words down in order and keep the paper somewhere safe. "
    + "The words restore your account, not your past message history.",
  legacy:
    "This account was created before backups existed, so it has no "
    + "recovery words. To get a backup, you'd need a fresh account — "
    + "your current one keeps working either way.",
} as const;

/// Template block `settings.ts` interpolates as its own section.
export const BACKUP_PANEL_HTML = `
      <p class="setting-desc" id="${BACKUP_IDS.intro}">${BACKUP_COPY.intro}</p>
      <div class="setting-row setting-row--stack">
        <button type="button" class="setting-action" id="${BACKUP_IDS.reveal}">${BACKUP_COPY.reveal}</button>
        <button type="button" class="setting-action setting-action-ghost" id="${BACKUP_IDS.hide}" hidden>${BACKUP_COPY.hide}</button>
      </div>
      <ol class="backup-words" id="${BACKUP_IDS.words}" hidden></ol>
      <p class="setting-desc" id="${BACKUP_IDS.note}" hidden>${BACKUP_COPY.note}</p>
      <p class="setting-error" id="${BACKUP_IDS.error}" role="alert" hidden></p>`;

/// Initialise the backup panel under a mount root (the Settings
/// overlay). Idempotent: repeated calls on the same root short-circuit
/// so reopening Settings doesn't double-bind handlers.
export function initBackupPanel(root: HTMLElement): void {
  const intro = root.querySelector<HTMLParagraphElement>(`#${BACKUP_IDS.intro}`);
  const reveal = root.querySelector<HTMLButtonElement>(`#${BACKUP_IDS.reveal}`);
  const words = root.querySelector<HTMLOListElement>(`#${BACKUP_IDS.words}`);
  const hide = root.querySelector<HTMLButtonElement>(`#${BACKUP_IDS.hide}`);
  const note = root.querySelector<HTMLParagraphElement>(`#${BACKUP_IDS.note}`);
  const errSlot = root.querySelector<HTMLParagraphElement>(`#${BACKUP_IDS.error}`);
  if (!intro || !reveal || !words || !hide || !note || !errSlot) return;
  if (reveal.dataset.bound === "1") return;
  reveal.dataset.bound = "1";

  const showError = (msg: string): void => {
    errSlot.hidden = false;
    errSlot.textContent = msg;
  };

  // Two-step reveal: first click arms (shows the shoulder-surfing
  // warning), second click fetches and shows the words.
  let armed = false;

  const hideWords = (): void => {
    words.replaceChildren();
    words.hidden = true;
    note.hidden = true;
    hide.hidden = true;
    reveal.hidden = false;
    reveal.textContent = BACKUP_COPY.reveal;
    intro.textContent = BACKUP_COPY.intro;
    armed = false;
  };

  const showWords = (phrase: string): void => {
    words.replaceChildren(
      ...phrase.split(/\s+/).map((word) => {
        const li = document.createElement("li");
        li.textContent = word;
        return li;
      }),
    );
    words.hidden = false;
    note.hidden = false;
    hide.hidden = false;
    reveal.hidden = true;
  };

  reveal.addEventListener("click", () => {
    errSlot.hidden = true;
    errSlot.textContent = "";
    if (!armed) {
      armed = true;
      intro.textContent = BACKUP_COPY.confirm;
      reveal.textContent = BACKUP_COPY.confirmReveal;
      return;
    }
    void (async () => {
      try {
        const phrase = await invoke<string | null>("chat_reveal_recovery_phrase");
        if (phrase === null) {
          intro.textContent = BACKUP_COPY.legacy;
          reveal.hidden = true;
          return;
        }
        showWords(phrase);
      } catch (e) {
        showError(String(e));
        hideWords();
      }
    })();
  });

  hide.addEventListener("click", hideWords);
}
