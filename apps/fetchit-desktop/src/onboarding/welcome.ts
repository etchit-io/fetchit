// First-run welcome overlay. One question (display name), honest key
// custody copy, Start enables chat live, Skip just marks done. Gated
// by the persisted onboarding_done settings flag so it shows once.

import { invoke } from "@tauri-apps/api/core";

export const ONBOARDING_COPY = {
  title: "Welcome to fetch>it",
  question: "What should we call you?",
  honesty:
    "Your chat keys are created on this device and stay only here. "
    + "If you switch computers you start fresh, and add your people "
    + "again with a QR code. Nothing about you is stored in any cloud.",
  start: "Start",
  skip: "Skip for now",
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

  card.append(title, label, honesty, start, skip);
  root.append(card);
  host.append(root);
  host.hidden = false;
  input.focus();

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
