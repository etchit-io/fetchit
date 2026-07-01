// In-app confirm dialog, styled to match the chat dialogs. Replaces
// the tauri-plugin-dialog global confirm() that is broken in 2.7.x
// (its injected window.confirm calls a `plugin:dialog|confirm`
// command that no longer exists Rust-side).
//
// Reuses one host element on document.body. The host is pre-styled
// with the `chat-dialog` class + `hidden=true` at first use; only
// hidden / labels / handlers change per invocation, never the class
// or DOM structure. That matters: webkit2gtk on Linux wedges its
// compositor when a hidden overlay gets its positioning class and
// its first children in the same task.

interface ConfirmHost {
  host: HTMLDivElement;
  titleEl: HTMLHeadingElement;
  msgEl: HTMLParagraphElement;
  okBtn: HTMLButtonElement;
  cancelBtn: HTMLButtonElement;
}

let hostRef: ConfirmHost | null = null;

function ensureHost(): ConfirmHost {
  if (hostRef) return hostRef;

  const host = document.createElement("div");
  host.className = "chat-dialog";
  host.hidden = true;

  const panel = document.createElement("div");
  panel.className = "chat-dialog__panel";

  const titleEl = document.createElement("h3");

  const msgEl = document.createElement("p");
  msgEl.className = "chat-dialog__help";

  const actions = document.createElement("div");
  actions.className = "chat-dialog__actions";

  const okBtn = document.createElement("button");
  okBtn.type = "button";
  okBtn.className = "chat-dialog__btn";

  const cancelBtn = document.createElement("button");
  cancelBtn.type = "button";
  cancelBtn.className = "chat-dialog__btn chat-dialog__btn--ghost";

  actions.appendChild(okBtn);
  actions.appendChild(cancelBtn);

  panel.appendChild(titleEl);
  panel.appendChild(msgEl);
  panel.appendChild(actions);

  host.appendChild(panel);
  document.body.appendChild(host);

  hostRef = { host, titleEl, msgEl, okBtn, cancelBtn };
  return hostRef;
}

/// Options for [`chatConfirm`].
export interface ChatConfirmOptions {
  /// Bold heading at the top of the dialog (e.g. "Leave group").
  title: string;
  /// Body copy explaining what the user is about to do.
  message: string;
  /// Label for the confirmation button. Defaults to "OK".
  confirmLabel?: string;
  /// Label for the cancel button. Defaults to "Cancel".
  cancelLabel?: string;
}

/// Show a styled confirm prompt and resolve with the user's choice.
/// Clicking outside the panel counts as cancel.
export function chatConfirm(opts: ChatConfirmOptions): Promise<boolean> {
  const ctx = ensureHost();

  ctx.titleEl.textContent = opts.title;
  ctx.msgEl.textContent = opts.message;
  ctx.okBtn.textContent = opts.confirmLabel ?? "OK";
  ctx.cancelBtn.textContent = opts.cancelLabel ?? "Cancel";

  return new Promise((resolve) => {
    const close = (result: boolean): void => {
      ctx.host.hidden = true;
      ctx.okBtn.onclick = null;
      ctx.cancelBtn.onclick = null;
      ctx.host.onclick = null;
      resolve(result);
    };

    ctx.okBtn.onclick = () => close(true);
    ctx.cancelBtn.onclick = () => close(false);
    ctx.host.onclick = (e) => {
      if (e.target === ctx.host) close(false);
    };

    ctx.host.hidden = false;
  });
}
