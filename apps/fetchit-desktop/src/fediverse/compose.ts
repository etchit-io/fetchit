// Compose half of the M4 fediverse pane: opt-in actor mint, the
// public-post composer, and the mandatory publish confirmation modal.
// Everything here is the C privacy contract (observably public) - the
// chrome says so and the modal makes the user say it back once per
// session. The pane host mounts this under the feed; no network code
// beyond the three fediverse_* Tauri commands.

import { invoke } from "@tauri-apps/api/core";

/// Mirror of the backend PublishReportDto.
export interface PublishReport {
  delivered: string[];
  failed: [string, string][];
}

/// Imperative handle the pane uses to wire reply-publicly from feed cards.
export interface ComposeApi {
  element: HTMLElement;
  /// Resolves once the actor status loaded and the right view rendered.
  ready: Promise<void>;
  /// Target a public reply at a verified actor URL (from a feed card).
  setReplyTo(actorUrl: string): void;
  clearReplyTo(): void;
}

/// Spec copy for the mandatory confirmation modal - verbatim, do not
/// reword without updating the M4 design doc.
export const CONFIRM_COPY =
  "Post publicly to the fediverse. This is visible to operators, " +
  "instance admins, and any subscriber of your actor. Anyone you " +
  "mention can see it; your community denylist is the only filter.";

/// Client-side mirror of the crate-side handle validator
/// (`[A-Za-z0-9_-]`, 1-64 chars). The crate stays authoritative.
const HANDLE_RE = /^[A-Za-z0-9_-]{1,64}$/;

// Session-scoped "don't ask again" - deliberately NOT persisted; a new
// app session must re-confirm the public contract once.
let skipConfirmThisSession = false;

/// Test hook: reset the session confirmation latch.
export function resetConfirmForTests(): void {
  skipConfirmThisSession = false;
}

/// Mount the compose surface into `host`.
export function mountCompose(host: HTMLElement): ComposeApi {
  host.replaceChildren();
  host.className = "fediverse-compose";

  let replyTo: string | null = null;

  const replyChip = document.createElement("div");
  replyChip.className = "fediverse-compose__reply";
  replyChip.hidden = true;
  const replyLabel = document.createElement("span");
  replyLabel.className = "fediverse-compose__reply-label";
  const replyClear = document.createElement("button");
  replyClear.type = "button";
  replyClear.className = "fediverse-compose__reply-clear";
  replyClear.setAttribute("aria-label", "Clear reply target");
  replyClear.textContent = "×";
  replyChip.append(replyLabel, replyClear);

  const clearReplyTo = (): void => {
    replyTo = null;
    replyChip.hidden = true;
    replyLabel.textContent = "";
  };
  replyClear.addEventListener("click", clearReplyTo);

  const setReplyTo = (actorUrl: string): void => {
    replyTo = actorUrl;
    replyLabel.textContent = `replying publicly to ${actorUrl}`;
    replyChip.hidden = false;
  };

  const result = document.createElement("div");
  result.className = "fediverse-compose__result";

  const renderComposer = (): void => {
    const textarea = document.createElement("textarea");
    textarea.className = "fediverse-compose__textarea";
    textarea.placeholder = "Write a public post… (@user@host mentions deliver directly)";
    textarea.rows = 3;

    const note = document.createElement("span");
    note.className = "fediverse-compose__note";
    note.textContent = "Public · not encrypted";

    const postBtn = document.createElement("button");
    postBtn.type = "button";
    postBtn.className = "fediverse-compose__post";
    postBtn.textContent = "Post publicly";

    const footer = document.createElement("div");
    footer.className = "fediverse-compose__footer";
    footer.append(note, postBtn);

    const publish = async (): Promise<void> => {
      const bodyMd = textarea.value.trim();
      if (!bodyMd) return;
      postBtn.disabled = true;
      result.textContent = "";
      try {
        const report = await invoke<PublishReport>("fediverse_publish", {
          bodyMd,
          replyToActorUrl: replyTo,
        });
        const total = report.delivered.length + report.failed.length;
        result.textContent =
          total === 0
            ? "Posted (no mentions, so no direct deliveries)"
            : `delivered ${report.delivered.length} · failed ${report.failed.length}`;
        textarea.value = "";
        clearReplyTo();
      } catch (e) {
        result.textContent = `Publish failed: ${String(e)}`;
      } finally {
        postBtn.disabled = false;
      }
    };

    postBtn.addEventListener("click", () => {
      if (!textarea.value.trim()) return;
      if (skipConfirmThisSession) {
        void publish();
        return;
      }
      postBtn.disabled = true;
      openConfirmModal(
        host,
        () => void publish(),
        () => {
          postBtn.disabled = false;
        },
      );
    });

    host.append(replyChip, textarea, footer, result);
  };

  const renderMint = (): void => {
    const heading = document.createElement("div");
    heading.className = "fediverse-compose__mint-heading";
    heading.textContent = "Choose your public handle";

    const help = document.createElement("div");
    help.className = "fediverse-compose__mint-help";
    help.textContent =
      "Public posting is opt-in and separate from your chat identity. " +
      "Letters, digits, - and _ only.";

    const input = document.createElement("input");
    input.type = "text";
    input.className = "fediverse-compose__mint-input";
    input.placeholder = "handle";
    input.spellcheck = false;

    const error = document.createElement("div");
    error.className = "fediverse-compose__mint-error";

    const mintBtn = document.createElement("button");
    mintBtn.type = "button";
    mintBtn.className = "fediverse-compose__mint-btn";
    mintBtn.textContent = "Create public handle";

    mintBtn.addEventListener("click", () => {
      const handle = input.value.trim();
      if (!HANDLE_RE.test(handle)) {
        error.textContent = "Handles are 1-64 chars: letters, digits, - or _";
        return;
      }
      error.textContent = "";
      mintBtn.disabled = true;
      void invoke<string>("fediverse_mint", { handle })
        .then(() => {
          host.replaceChildren();
          renderComposer();
        })
        .catch((e: unknown) => {
          error.textContent = `Could not create handle: ${String(e)}`;
          mintBtn.disabled = false;
        });
    });

    host.append(heading, help, input, error, mintBtn);
  };

  const ready = invoke<string | null>("fediverse_actor_status")
    .then((handle) => {
      if (handle) {
        renderComposer();
      } else {
        renderMint();
      }
    })
    .catch(() => {
      renderMint();
    });

  return { element: host, ready, setReplyTo, clearReplyTo };
}

/// Build + show the confirmation modal. `onAccept` runs only on the
/// primary action, `onCancel` only on dismissal; the modal gates the
/// publish call, the backend never re-asks.
function openConfirmModal(
  host: HTMLElement,
  onAccept: () => void,
  onCancel: () => void,
): void {
  const overlay = document.createElement("div");
  overlay.className = "fediverse-confirm";

  const box = document.createElement("div");
  box.className = "fediverse-confirm__box";

  const copy = document.createElement("p");
  copy.className = "fediverse-confirm__copy";
  copy.textContent = CONFIRM_COPY;

  const tickRow = document.createElement("label");
  tickRow.className = "fediverse-confirm__tick";
  const tick = document.createElement("input");
  tick.type = "checkbox";
  const tickLabel = document.createElement("span");
  tickLabel.textContent = "Don't ask again for this session";
  tickRow.append(tick, tickLabel);

  const cancelBtn = document.createElement("button");
  cancelBtn.type = "button";
  cancelBtn.className = "fediverse-confirm__cancel";
  cancelBtn.textContent = "Cancel";

  const acceptBtn = document.createElement("button");
  acceptBtn.type = "button";
  acceptBtn.className = "fediverse-confirm__accept";
  acceptBtn.textContent = "Post publicly";

  const buttons = document.createElement("div");
  buttons.className = "fediverse-confirm__buttons";
  buttons.append(cancelBtn, acceptBtn);

  box.append(copy, tickRow, buttons);
  overlay.append(box);
  host.append(overlay);

  cancelBtn.addEventListener("click", () => {
    overlay.remove();
    onCancel();
  });
  acceptBtn.addEventListener("click", () => {
    if (tick.checked) {
      skipConfirmThisSession = true;
    }
    overlay.remove();
    onAccept();
  });
}
