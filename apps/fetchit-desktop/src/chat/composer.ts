// Multi-line composer at the bottom of the conversation pane.
// Enter sends; Shift+Enter inserts a newline.

export interface ComposerHandlers {
  /// Fire-and-forget. The orchestrator owns the bubble lifecycle —
  /// the composer just clears its input and lets the store represent
  /// delivery state via bubble status icons.
  onSend: (body: string) => void;
}

export function mountComposer(
  root: HTMLElement,
  handlers: ComposerHandlers,
): { focus: () => void } {
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

  const trySend = (): void => {
    const body = ta.value.trim();
    if (!body) return;
    ta.value = "";
    tryGrow();
    send.disabled = true;
    handlers.onSend(body);
  };

  ta.addEventListener("input", () => {
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

  return {
    focus: () => ta.focus(),
  };
}
