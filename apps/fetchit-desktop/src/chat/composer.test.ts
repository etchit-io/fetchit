import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mountComposer } from "./composer";

let host: HTMLElement;

beforeEach(() => {
  host = document.createElement("div");
  document.body.appendChild(host);
});

afterEach(() => {
  host.remove();
});

function setup(onSend = vi.fn()): {
  api: ReturnType<typeof mountComposer>;
  ta: HTMLTextAreaElement;
  send: HTMLButtonElement;
  onSend: ReturnType<typeof vi.fn>;
} {
  const api = mountComposer(host, { onSend });
  const ta = host.querySelector<HTMLTextAreaElement>(".chat-composer__input")!;
  const send = host.querySelector<HTMLButtonElement>(".chat-composer__send")!;
  return { api, ta, send, onSend };
}

describe("mountComposer — basic send flow", () => {
  it("fires onSend with the trimmed body when Send is clicked", () => {
    const { ta, send, onSend } = setup();
    ta.value = "  hello world  ";
    ta.dispatchEvent(new Event("input"));
    send.click();
    expect(onSend).toHaveBeenCalledWith("hello world", null, null);
  });

  it("clears the textarea on successful send", () => {
    const { ta, send } = setup();
    ta.value = "hi";
    ta.dispatchEvent(new Event("input"));
    send.click();
    expect(ta.value).toBe("");
  });

  it("Enter sends, Shift+Enter inserts a newline", () => {
    const { ta, onSend } = setup();
    ta.value = "line";
    ta.dispatchEvent(new Event("input"));
    const enter = new KeyboardEvent("keydown", { key: "Enter" });
    ta.dispatchEvent(enter);
    expect(onSend).toHaveBeenCalledTimes(1);
    onSend.mockReset();
    ta.value = "again";
    ta.dispatchEvent(new Event("input"));
    const shiftEnter = new KeyboardEvent("keydown", {
      key: "Enter",
      shiftKey: true,
    });
    ta.dispatchEvent(shiftEnter);
    expect(onSend).not.toHaveBeenCalled();
  });
});

describe("mountComposer — setEnabled", () => {
  it("disables textarea + Send, sets the hint placeholder", () => {
    const { api, ta, send } = setup();
    api.setEnabled(false, "Select a conversation to start writing…");
    expect(ta.disabled).toBe(true);
    expect(send.disabled).toBe(true);
    expect(ta.placeholder).toBe("Select a conversation to start writing…");
  });

  it("re-enables and restores the default placeholder", () => {
    const { api, ta, send } = setup();
    api.setEnabled(false, "no conv");
    api.setEnabled(true);
    expect(ta.disabled).toBe(false);
    expect(ta.placeholder).toBe("Write a message…");
    // Send stays disabled because the textarea is empty.
    expect(send.disabled).toBe(true);
    ta.value = "hi";
    ta.dispatchEvent(new Event("input"));
    expect(send.disabled).toBe(false);
  });

  it("does not fire onSend while disabled, even via Enter", () => {
    const { api, ta, onSend } = setup();
    ta.value = "leaked";
    ta.dispatchEvent(new Event("input"));
    api.setEnabled(false, "no conv");
    ta.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter" }));
    expect(onSend).not.toHaveBeenCalled();
  });
});

describe("mountComposer — reply chip", () => {
  const ref = {
    messageId: "m1",
    senderName: "Bob",
    preview: "the original text",
  };

  function chip(): HTMLElement {
    return host.querySelector<HTMLElement>(".chat-composer__reply")!;
  }

  it("setReplyTo shows the chip with sender and preview", () => {
    const { api } = setup();
    api.setReplyTo(ref);
    expect(chip().hidden).toBe(false);
    expect(chip().querySelector(".chat-composer__reply-sender")!.textContent).toBe("Bob");
    expect(chip().querySelector(".chat-composer__reply-preview")!.textContent).toBe(
      "the original text",
    );
  });

  it("clear button dismisses the chip and the next send carries no reply", () => {
    const { api, ta, send, onSend } = setup();
    api.setReplyTo(ref);
    host.querySelector<HTMLButtonElement>(".chat-composer__reply-clear")!.click();
    expect(chip().hidden).toBe(true);
    ta.value = "no quote";
    ta.dispatchEvent(new Event("input"));
    send.click();
    expect(onSend).toHaveBeenCalledWith("no quote", null, null);
  });

  it("send carries the pending ref once, then clears", () => {
    const { api, ta, send, onSend } = setup();
    api.setReplyTo(ref);
    ta.value = "a reply";
    ta.dispatchEvent(new Event("input"));
    send.click();
    expect(onSend).toHaveBeenCalledWith("a reply", ref, null);
    expect(chip().hidden).toBe(true);
    ta.value = "second";
    ta.dispatchEvent(new Event("input"));
    send.click();
    expect(onSend).toHaveBeenLastCalledWith("second", null, null);
  });

  it("Escape clears the chip when the emoji picker is closed", () => {
    const { api, ta } = setup();
    api.setReplyTo(ref);
    ta.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
    expect(chip().hidden).toBe(true);
  });
});

describe("mountComposer — emoji picker", () => {
  function emojiBtn(): HTMLButtonElement {
    return host.querySelector<HTMLButtonElement>(".chat-composer__emoji button")!;
  }

  it("toggles the picker open and closed", () => {
    setup();
    expect(host.querySelector(".chat-emoji-picker")).toBeNull();
    emojiBtn().click();
    expect(host.querySelector(".chat-emoji-picker")).not.toBeNull();
    emojiBtn().click();
    expect(host.querySelector(".chat-emoji-picker")).toBeNull();
  });

  it("inserts the picked emoji at the cursor and enables Send", () => {
    const { ta, send } = setup();
    ta.value = "ab";
    ta.dispatchEvent(new Event("input"));
    ta.setSelectionRange(1, 1);
    emojiBtn().click();
    const cell = host.querySelector<HTMLButtonElement>(".chat-emoji-picker__cell")!;
    cell.click();
    expect(ta.value).toBe(`a${cell.textContent}b`);
    expect(send.disabled).toBe(false);
  });

  it("disables the emoji button and closes the picker when disabled", () => {
    const { api } = setup();
    emojiBtn().click();
    expect(host.querySelector(".chat-emoji-picker")).not.toBeNull();
    api.setEnabled(false, "no conv");
    expect(emojiBtn().disabled).toBe(true);
    expect(host.querySelector(".chat-emoji-picker")).toBeNull();
  });
});

describe("mountComposer — image attach", () => {
  const ATT = { mime: "image/png", width: 8, height: 6, bytes_b64: "AAA=" };

  function setupAttach(
    onSend = vi.fn(),
    buildAttachment = vi.fn().mockResolvedValue(ATT),
    onAttachError = vi.fn(),
  ): {
    api: ReturnType<typeof mountComposer>;
    send: HTMLButtonElement;
    attachBtn: HTMLButtonElement;
    file: HTMLInputElement;
    onSend: ReturnType<typeof vi.fn>;
    onAttachError: ReturnType<typeof vi.fn>;
  } {
    const api = mountComposer(host, { onSend, buildAttachment, onAttachError });
    const send = host.querySelector<HTMLButtonElement>(".chat-composer__send")!;
    const attachBtn = host.querySelector<HTMLButtonElement>(".chat-composer__attach")!;
    const file = host.querySelector<HTMLInputElement>(".chat-composer__file")!;
    return { api, send, attachBtn, file, onSend, onAttachError };
  }

  function pick(input: HTMLInputElement): void {
    const f = new File([new Uint8Array([1, 2, 3])], "pic.png", { type: "image/png" });
    Object.defineProperty(input, "files", { value: [f], configurable: true });
    input.dispatchEvent(new Event("change"));
  }

  function chip(): HTMLElement | null {
    return host.querySelector<HTMLElement>(".chat-composer__attachment:not([hidden])");
  }

  it("renders an attach button and a hidden image-only file input", () => {
    const { attachBtn, file } = setupAttach();
    expect(attachBtn).not.toBeNull();
    expect(file.getAttribute("type")).toBe("file");
    expect(file.getAttribute("accept")).toContain("image/");
  });

  it("stages a picked image: shows a preview chip and enables Send with empty body", async () => {
    const { send, file } = setupAttach();
    expect(send.disabled).toBe(true);
    pick(file);
    await vi.waitFor(() => expect(chip()).not.toBeNull());
    expect(send.disabled).toBe(false);
  });

  it("send carries the staged attachment, then clears it", async () => {
    const { send, file, onSend } = setupAttach();
    pick(file);
    await vi.waitFor(() => expect(chip()).not.toBeNull());
    send.click();
    expect(onSend).toHaveBeenCalledWith("", null, ATT);
    expect(chip()).toBeNull();
    expect(send.disabled).toBe(true);
  });

  it("remove button discards the staged attachment", async () => {
    const { send, file } = setupAttach();
    pick(file);
    await vi.waitFor(() => expect(chip()).not.toBeNull());
    host.querySelector<HTMLButtonElement>(".chat-composer__attachment-remove")!.click();
    expect(chip()).toBeNull();
    expect(send.disabled).toBe(true);
  });

  it("surfaces an invalid image via onAttachError and stages nothing", async () => {
    const buildAttachment = vi.fn().mockRejectedValue(new Error("Only JPEG, PNG, GIF, or WebP"));
    const onAttachError = vi.fn();
    const { file } = setupAttach(vi.fn(), buildAttachment, onAttachError);
    pick(file);
    await vi.waitFor(() => expect(onAttachError).toHaveBeenCalledWith("Only JPEG, PNG, GIF, or WebP"));
    expect(chip()).toBeNull();
  });

  it("disables the attach button when the composer is disabled", () => {
    const { api, attachBtn } = setupAttach();
    api.setEnabled(false, "no conv");
    expect(attachBtn.disabled).toBe(true);
  });

  it("clearAttachment discards a staged image (conversation change)", async () => {
    const { api, send, file } = setupAttach();
    pick(file);
    await vi.waitFor(() => expect(chip()).not.toBeNull());
    api.clearAttachment();
    expect(chip()).toBeNull();
    expect(send.disabled).toBe(true);
  });
});
