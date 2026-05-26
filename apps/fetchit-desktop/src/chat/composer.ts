// Multi-line composer at the bottom of the conversation pane.
// Enter sends; Shift+Enter inserts a newline.

export interface ComposerHandlers {
  /// Fire-and-forget. The orchestrator owns the bubble lifecycle —
  /// the composer just clears its input and lets the store represent
  /// delivery state via bubble status icons.
  onSend: (body: string) => void;
}

export interface ComposerApi {
  focus(): void;
  /// Toggle whether the composer accepts input. When disabled, the
  /// textarea is read-only, the Send button is greyed out, and the
  /// placeholder reflects the supplied hint. Used when no conversation
  /// is selected so typing-into-the-void can't happen.
  setEnabled(enabled: boolean, hint?: string): void;
}

export function mountComposer(
  root: HTMLElement,
  handlers: ComposerHandlers,
): ComposerApi {
  root.replaceChildren();
  root.className = "chat-composer";

  const ta = document.createElement("textarea");
  ta.className = "chat-composer__input";
  ta.placeholder = "Write a message…";
  ta.rows = 1;
  ta.setAttribute("aria-label", "Compose message");

  const send = document.createElement("button");
  send.type = "button";
  send.className = "chat-composer__send";
  send.textContent = "Send";
  send.disabled = true;

  const tryGrow = (): void => {
    ta.style.height = "auto";
    const max = 6 * 22; // ~6 rows
    ta.style.height = `${Math.min(ta.scrollHeight, max)}px`;
  };

  let enabled = true;
  const DEFAULT_PLACEHOLDER = "Write a message…";

  const trySend = (): void => {
    if (!enabled) return;
    const body = ta.value.trim();
    if (!body) return;
    ta.value = "";
    tryGrow();
    send.disabled = true;
    handlers.onSend(body);
  };

  ta.addEventListener("input", () => {
    if (!enabled) return;
    send.disabled = ta.value.trim().length === 0;
    tryGrow();
  });

  ta.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      trySend();
    }
  });

  send.addEventListener("click", trySend);

  root.appendChild(ta);
  root.appendChild(send);

  const setEnabled = (next: boolean, hint?: string): void => {
    enabled = next;
    ta.disabled = !next;
    if (!next) {
      ta.placeholder = hint ?? DEFAULT_PLACEHOLDER;
      send.disabled = true;
    } else {
      ta.placeholder = DEFAULT_PLACEHOLDER;
      send.disabled = ta.value.trim().length === 0;
    }
  };

  return {
    focus: () => ta.focus(),
    setEnabled,
  };
}
