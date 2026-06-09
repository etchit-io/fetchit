// Multi-line composer at the bottom of the conversation pane.
// Enter sends; Shift+Enter inserts a newline.

import { icon } from "../ui/icons";
import { createEmojiPicker } from "./emojiPicker";

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

  // Emoji affordance: a toggle button that floats a picker above it.
  const emojiWrap = document.createElement("div");
  emojiWrap.className = "chat-composer__emoji";
  const emojiBtn = document.createElement("button");
  emojiBtn.type = "button";
  emojiBtn.className = "chat-icon-btn";
  emojiBtn.title = "Emoji";
  emojiBtn.setAttribute("aria-label", "Emoji");
  emojiBtn.setAttribute("aria-expanded", "false");
  emojiBtn.appendChild(icon("emoji"));
  emojiWrap.appendChild(emojiBtn);

  const send = document.createElement("button");
  send.type = "button";
  send.className = "chat-composer__send";
  send.title = "Send";
  send.setAttribute("aria-label", "Send");
  send.appendChild(icon("send"));
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

  // Emoji picker open/close + insert-at-cursor. Function declarations so
  // the close/open/listener helpers can reference each other freely; the
  // document listeners exist only while the picker is open.
  let picker: HTMLElement | null = null;

  function insertEmoji(emoji: string): void {
    const start = ta.selectionStart ?? ta.value.length;
    const end = ta.selectionEnd ?? ta.value.length;
    ta.value = ta.value.slice(0, start) + emoji + ta.value.slice(end);
    const pos = start + emoji.length;
    ta.setSelectionRange(pos, pos);
    ta.focus();
    ta.dispatchEvent(new Event("input"));
  }

  function onDocPointerDown(e: PointerEvent): void {
    if (!emojiWrap.contains(e.target as Node)) closePicker();
  }

  function onPickerKeydown(e: KeyboardEvent): void {
    if (e.key === "Escape") {
      closePicker();
      ta.focus();
    }
  }

  function openPicker(): void {
    if (picker) return;
    picker = createEmojiPicker(insertEmoji);
    emojiWrap.appendChild(picker);
    emojiBtn.setAttribute("aria-expanded", "true");
    document.addEventListener("pointerdown", onDocPointerDown, true);
    document.addEventListener("keydown", onPickerKeydown, true);
  }

  function closePicker(): void {
    if (!picker) return;
    picker.remove();
    picker = null;
    emojiBtn.setAttribute("aria-expanded", "false");
    document.removeEventListener("pointerdown", onDocPointerDown, true);
    document.removeEventListener("keydown", onPickerKeydown, true);
  }

  emojiBtn.addEventListener("click", () => {
    if (!enabled) return;
    if (picker) closePicker();
    else openPicker();
  });

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
  root.appendChild(emojiWrap);
  root.appendChild(send);

  const setEnabled = (next: boolean, hint?: string): void => {
    enabled = next;
    ta.disabled = !next;
    emojiBtn.disabled = !next;
    if (!next) {
      closePicker();
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
