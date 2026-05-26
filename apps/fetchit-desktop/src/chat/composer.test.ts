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
    expect(onSend).toHaveBeenCalledWith("hello world");
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
