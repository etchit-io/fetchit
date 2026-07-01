// First-run welcome overlay. One question (display name), honest key
// custody copy, Start enables chat live, Skip just marks done. Gated
// by the persisted onboarding_done settings flag so it shows once.

import { invoke } from "@tauri-apps/api/core";

export const ONBOARDING_COPY = {
  title: "Welcome to fetch>it",
  question: "What should we call you?",
  honesty:
    "Your chat keys are created on this device and stay only here — "
    + "nothing about you is stored in any cloud. You can write your "
    + "identity down as 24 words any time in Settings → Identity backup, "
    + "and bring it to a new computer.",
  start: "Start",
  skip: "Skip for now",
  restoreLink: "I already have a recovery phrase",
  restoreQuestion: "Type your 24 words, in order",
  restorePlaceholder: "apple banana cherry …",
  restoreGo: "Restore my identity",
  restoreBack: "Back",
  restoreDone: "Identity restored — restarting fetch>it…",
  restoreNote:
    "Restoring brings your identity to this computer. Messages from "
    + "your old device don't come along — history lives on each device.",
} as const;

const NAME_MAX = 64;

export interface OnboardingOpts {
  /// Called after Start succeeds AND the resolved chat flag is on.
  /// The controller mounts the chat surface and opens the panel here;
  /// the panel's own bootstrap mints the identity (and renders the
  /// human card on failure).
  onChatStart: () => Promise<void> | void;
}

/// Mount the overlay into `host` unless onboarding is already done.
export async function initOnboarding(host: HTMLElement, opts: OnboardingOpts): Promise<void> {
  const done = await invoke<boolean>("onboarding_done").catch(() => true);
  if (done) return;

  const root = document.createElement("div");
  root.className = "onboarding";

  const card = document.createElement("div");
  card.className = "onboarding__card";

  const title = document.createElement("h1");
  title.className = "onboarding__title";
  title.textContent = ONBOARDING_COPY.title;

  const label = document.createElement("label");
  label.className = "onboarding__question";
  label.textContent = ONBOARDING_COPY.question;

  const input = document.createElement("input");
  input.className = "onboarding__name";
  input.type = "text";
  input.maxLength = NAME_MAX;
  input.placeholder = "Your name";
  label.append(input);

  const honesty = document.createElement("p");
  honesty.className = "onboarding__honesty";
  honesty.textContent = ONBOARDING_COPY.honesty;

  const start = document.createElement("button");
  start.className = "onboarding__start";
  start.type = "button";
  start.textContent = ONBOARDING_COPY.start;
  start.disabled = true;

  const skip = document.createElement("button");
  skip.className = "onboarding__skip";
  skip.type = "button";
  skip.textContent = ONBOARDING_COPY.skip;

  const restoreLink = document.createElement("button");
  restoreLink.className = "onboarding__restore-link";
  restoreLink.type = "button";
  restoreLink.textContent = ONBOARDING_COPY.restoreLink;

  card.append(title, label, honesty, start, skip, restoreLink);
  root.append(card);
  host.append(root);
  host.hidden = false;
  input.focus();

  // Restore mode: swaps the card body for a phrase entry. Kept in the
  // same overlay so Back returns without losing the typed name.
  restoreLink.addEventListener("click", () => {
    mountRestore(card, {
      back: () => {
        restoreCard.remove();
        for (const el of [title, label, honesty, start, skip, restoreLink]) el.hidden = false;
        input.focus();
      },
    });
    const restoreCard = card.lastElementChild as HTMLElement;
    for (const el of [title, label, honesty, start, skip, restoreLink]) el.hidden = true;
  });

  const validName = (): string | null => {
    const name = input.value.trim();
    return name.length >= 1 && name.length <= NAME_MAX ? name : null;
  };
  input.addEventListener("input", () => {
    start.disabled = validName() === null;
  });

  const finish = (): void => {
    host.hidden = true;
    root.remove();
  };

  start.addEventListener("click", () => {
    const name = validName();
    if (name === null) return;
    start.disabled = true;
    void (async () => {
      try {
        await invoke("set_display_name", { name });
        const resolved = await invoke<boolean>("set_chat_enabled", { enabled: true });
        await invoke("set_onboarding_done");
        finish();
        if (resolved) await opts.onChatStart();
      } catch (e) {
        console.error("[onboarding] start failed:", e);
        // Still complete: the reader must never be held hostage by a
        // chat bootstrap problem. The chat panel surfaces its own
        // human card on open.
        await invoke("set_onboarding_done").catch(() => {});
        finish();
      }
    })();
  });

  skip.addEventListener("click", () => {
    void invoke("set_onboarding_done").catch(() => {});
    finish();
  });
}

/// Mount the restore-from-phrase form into `card`. On success the app
/// restarts (boot re-seeds the daemon's agent key from the restored
/// vault), so there is deliberately no post-success path here.
function mountRestore(card: HTMLElement, opts: { back: () => void }): void {
  const wrap = document.createElement("div");
  wrap.className = "onboarding__restore";

  const q = document.createElement("p");
  q.className = "onboarding__question";
  q.textContent = ONBOARDING_COPY.restoreQuestion;

  const phrase = document.createElement("textarea");
  phrase.className = "onboarding__phrase";
  phrase.rows = 3;
  phrase.placeholder = ONBOARDING_COPY.restorePlaceholder;
  phrase.spellcheck = false;

  const note = document.createElement("p");
  note.className = "onboarding__honesty";
  note.textContent = ONBOARDING_COPY.restoreNote;

  const err = document.createElement("p");
  err.className = "onboarding__error";
  err.setAttribute("role", "alert");
  err.hidden = true;

  const go = document.createElement("button");
  go.className = "onboarding__start";
  go.type = "button";
  go.textContent = ONBOARDING_COPY.restoreGo;
  go.disabled = true;

  const back = document.createElement("button");
  back.className = "onboarding__skip";
  back.type = "button";
  back.textContent = ONBOARDING_COPY.restoreBack;

  // A BIP39 phrase is exactly 24 words; enable the button on shape, let
  // the checksum in the backend catch typos with a precise error.
  const wordCount = (): number => phrase.value.trim().split(/\s+/).filter(Boolean).length;
  phrase.addEventListener("input", () => {
    go.disabled = wordCount() !== 24;
  });

  go.addEventListener("click", () => {
    go.disabled = true;
    err.hidden = true;
    void (async () => {
      try {
        await invoke<string>("chat_restore_recovery_phrase", {
          phrase: phrase.value.trim(),
        });
        q.textContent = ONBOARDING_COPY.restoreDone;
        phrase.disabled = true;
        back.disabled = true;
        // Give the success line a beat to paint before the relaunch.
        setTimeout(() => void invoke("restart_app").catch(() => {}), 800);
      } catch (e) {
        err.hidden = false;
        err.textContent = String(e);
        go.disabled = false;
      }
    })();
  });

  back.addEventListener("click", opts.back);

  wrap.append(q, phrase, note, err, go, back);
  card.append(wrap);
  phrase.focus();
}
