// Multi-line composer at the bottom of the conversation pane.
// Enter sends; Shift+Enter inserts a newline.

import { icon } from "../ui/icons";
import { createEmojiPicker } from "./emojiPicker";
import { attachmentDataUrl, fileToAttachment } from "./imageAttach";
import type { QuotedRef } from "./state";
import type { Attachment } from "./types";

export interface ComposerHandlers {
  /// Fire-and-forget. The orchestrator owns the bubble lifecycle —
  /// the composer just clears its input and lets the store represent
  /// delivery state via bubble status icons. `replyTo` is the pending
  /// reply target when the user sent from an active reply chip;
  /// `attachment` is the staged inline image, when one is present.
  onSend: (
    body: string,
    replyTo: QuotedRef | null,
    attachment: Attachment | null,
  ) => void;
  /// Build a validated [`Attachment`] from a picked file. Injectable for
  /// tests; defaults to [`fileToAttachment`]. Rejects on an invalid or
  /// oversize image.
  buildAttachment?: (file: File) => Promise<Attachment>;
  /// Surface an attach failure (invalid/oversize image) to the user.
  onAttachError?: (message: string) => void;
}

export interface ComposerApi {
  focus(): void;
  /// Toggle whether the composer accepts input. When disabled, the
  /// textarea is read-only, the Send button is greyed out, and the
  /// placeholder reflects the supplied hint. Used when no conversation
  /// is selected so typing-into-the-void can't happen.
  setEnabled(enabled: boolean, hint?: string): void;
  /// Show (or clear, with null) the reply chip above the input. The
  /// next send carries the ref; sending or dismissing clears it.
  setReplyTo(ref: QuotedRef | null): void;
  /// Show or hide the attach affordance. Hidden for conversations that
  /// cannot carry an inline image (groups), so the button never makes a
  /// promise the wire can't keep. Hiding also clears any staged image.
  setAttachVisible(visible: boolean): void;
  /// Discard any staged image. Called on conversation change so a
  /// picture chosen for one peer never sends to the next.
  clearAttachment(): void;
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

  // Attach affordance: a button that opens an image-only file picker,
  // plus the hidden input it drives.
  const fileInput = document.createElement("input");
  fileInput.type = "file";
  fileInput.className = "chat-composer__file";
  fileInput.accept = "image/jpeg,image/png,image/gif,image/webp";
  fileInput.hidden = true;

  const attachBtn = document.createElement("button");
  attachBtn.type = "button";
  attachBtn.className = "chat-icon-btn chat-composer__attach";
  attachBtn.title = "Attach image";
  attachBtn.setAttribute("aria-label", "Attach image");
  attachBtn.appendChild(icon("attach"));

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

  // Reply chip — hidden until the orchestrator hands us a quote target.
  const replyChip = document.createElement("div");
  replyChip.className = "chat-composer__reply";
  replyChip.hidden = true;
  const replySender = document.createElement("span");
  replySender.className = "chat-composer__reply-sender";
  const replyPreview = document.createElement("span");
  replyPreview.className = "chat-composer__reply-preview";
  const replyClear = document.createElement("button");
  replyClear.type = "button";
  replyClear.className = "chat-composer__reply-clear";
  replyClear.title = "Cancel reply";
  replyClear.setAttribute("aria-label", "Cancel reply");
  replyClear.textContent = "×";
  replyChip.append(replySender, replyPreview, replyClear);

  // Attachment chip — a thumbnail + dimensions + remove, shown while an
  // image is staged for the next send.
  const attachChip = document.createElement("div");
  attachChip.className = "chat-composer__attachment";
  attachChip.hidden = true;
  const attachThumb = document.createElement("img");
  attachThumb.className = "chat-composer__attachment-thumb";
  attachThumb.alt = "attachment preview";
  attachThumb.draggable = false;
  const attachLabel = document.createElement("span");
  attachLabel.className = "chat-composer__attachment-label";
  const attachRemove = document.createElement("button");
  attachRemove.type = "button";
  attachRemove.className = "chat-composer__attachment-remove";
  attachRemove.title = "Remove image";
  attachRemove.setAttribute("aria-label", "Remove image");
  attachRemove.textContent = "×";
  attachChip.append(attachThumb, attachLabel, attachRemove);

  const tryGrow = (): void => {
    ta.style.height = "auto";
    const max = 6 * 22; // ~6 rows
    ta.style.height = `${Math.min(ta.scrollHeight, max)}px`;
  };

  let enabled = true;
  let pendingReply: QuotedRef | null = null;
  let pendingAttachment: Attachment | null = null;
  const DEFAULT_PLACEHOLDER = "Write a message…";

  // Send is live when the composer is enabled and there is something to
  // send — body text or a staged image.
  const refreshSend = (): void => {
    send.disabled = !(enabled && (ta.value.trim().length > 0 || pendingAttachment !== null));
  };

  const setReplyTo = (ref: QuotedRef | null): void => {
    pendingReply = ref;
    if (ref) {
      replySender.textContent = ref.senderName;
      replyPreview.textContent = ref.preview;
      replyChip.hidden = false;
      if (enabled) ta.focus();
    } else {
      replyChip.hidden = true;
    }
  };

  const stageAttachment = (att: Attachment): void => {
    pendingAttachment = att;
    attachThumb.src = attachmentDataUrl(att);
    attachLabel.textContent = `${att.width}×${att.height}`;
    attachChip.hidden = false;
    refreshSend();
    if (enabled) ta.focus();
  };

  const clearAttachment = (): void => {
    pendingAttachment = null;
    attachChip.hidden = true;
    attachThumb.removeAttribute("src");
    refreshSend();
  };

  replyClear.addEventListener("click", () => {
    setReplyTo(null);
    ta.focus();
  });

  attachRemove.addEventListener("click", () => {
    clearAttachment();
    ta.focus();
  });

  attachBtn.addEventListener("click", () => {
    if (!enabled) return;
    // Reset so re-picking the same file still fires `change`.
    fileInput.value = "";
    fileInput.click();
  });

  fileInput.addEventListener("change", () => {
    const file = fileInput.files?.[0];
    if (!file) return;
    const build = handlers.buildAttachment ?? fileToAttachment;
    void build(file)
      .then(stageAttachment)
      .catch((e) => handlers.onAttachError?.((e as Error).message));
  });

  const trySend = (): void => {
    if (!enabled) return;
    const body = ta.value.trim();
    if (!body && !pendingAttachment) return;
    const att = pendingAttachment;
    ta.value = "";
    clearAttachment();
    tryGrow();
    handlers.onSend(body, pendingReply, att);
    setReplyTo(null);
    refreshSend();
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
    refreshSend();
    tryGrow();
  });

  ta.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      trySend();
    } else if (e.key === "Escape" && !picker && pendingReply) {
      // Picker-open Escape belongs to the picker's own handler.
      setReplyTo(null);
    }
  });

  send.addEventListener("click", trySend);

  const inputRow = document.createElement("div");
  inputRow.className = "chat-composer__row";
  inputRow.appendChild(ta);
  inputRow.appendChild(attachBtn);
  inputRow.appendChild(emojiWrap);
  inputRow.appendChild(send);
  root.appendChild(replyChip);
  root.appendChild(attachChip);
  root.appendChild(inputRow);
  root.appendChild(fileInput);

  const setEnabled = (next: boolean, hint?: string): void => {
    enabled = next;
    ta.disabled = !next;
    emojiBtn.disabled = !next;
    attachBtn.disabled = !next;
    if (!next) {
      closePicker();
      ta.placeholder = hint ?? DEFAULT_PLACEHOLDER;
    } else {
      ta.placeholder = DEFAULT_PLACEHOLDER;
    }
    refreshSend();
  };

  const setAttachVisible = (visible: boolean): void => {
    attachBtn.hidden = !visible;
    if (!visible) clearAttachment();
  };

  return {
    focus: () => ta.focus(),
    setEnabled,
    setReplyTo,
    setAttachVisible,
    clearAttachment,
  };
}
