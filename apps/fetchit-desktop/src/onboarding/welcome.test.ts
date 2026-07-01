import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

// eslint-disable-next-line import/first
import { invoke } from "@tauri-apps/api/core";
// eslint-disable-next-line import/first
import { ONBOARDING_COPY, initOnboarding } from "./welcome";

type InvokeMock = ReturnType<typeof vi.fn>;

beforeEach(() => {
  (invoke as InvokeMock).mockReset();
  document.body.innerHTML = "";
});

function host(): HTMLElement {
  const el = document.createElement("section");
  el.hidden = true;
  document.body.append(el);
  return el;
}

describe("initOnboarding", () => {
  it("stays hidden when onboarding is already done", async () => {
    (invoke as InvokeMock).mockResolvedValue(true);
    const h = host();
    await initOnboarding(h, { onChatStart: vi.fn() });
    expect(h.hidden).toBe(true);
    expect(h.querySelector(".onboarding")).toBeNull();
  });

  it("renders the overlay with the locked honesty copy on first run", async () => {
    (invoke as InvokeMock).mockResolvedValue(false);
    const h = host();
    await initOnboarding(h, { onChatStart: vi.fn() });
    expect(h.hidden).toBe(false);
    // The copy must tell the truth about backup: the identity is
    // recoverable via the 24-word phrase, never "you start fresh".
    expect(h.textContent).toContain(ONBOARDING_COPY.honesty);
    expect(ONBOARDING_COPY.honesty).toContain("24 words");
    expect(ONBOARDING_COPY.honesty).not.toContain("start fresh");
  });

  it("keeps Start disabled until a 1..=64 char name is typed", async () => {
    (invoke as InvokeMock).mockResolvedValue(false);
    const h = host();
    await initOnboarding(h, { onChatStart: vi.fn() });
    const input = h.querySelector<HTMLInputElement>(".onboarding__name")!;
    const start = h.querySelector<HTMLButtonElement>(".onboarding__start")!;
    expect(start.disabled).toBe(true);
    input.value = "   ";
    input.dispatchEvent(new Event("input"));
    expect(start.disabled).toBe(true);
    input.value = "x".repeat(65);
    input.dispatchEvent(new Event("input"));
    expect(start.disabled).toBe(true);
    input.value = "Grandma";
    input.dispatchEvent(new Event("input"));
    expect(start.disabled).toBe(false);
  });

  it("Start saves the name, enables chat, marks done, then hands off", async () => {
    const calls: string[] = [];
    (invoke as InvokeMock).mockImplementation((cmd: string) => {
      calls.push(cmd);
      if (cmd === "onboarding_done") return Promise.resolve(false);
      if (cmd === "set_chat_enabled") return Promise.resolve(true);
      return Promise.resolve(null);
    });
    const onChatStart = vi.fn().mockResolvedValue(undefined);
    const h = host();
    await initOnboarding(h, { onChatStart });
    const input = h.querySelector<HTMLInputElement>(".onboarding__name")!;
    input.value = " Grandma ";
    input.dispatchEvent(new Event("input"));
    h.querySelector<HTMLButtonElement>(".onboarding__start")!.click();
    await vi.waitFor(() => expect(h.hidden).toBe(true));
    expect(invoke).toHaveBeenCalledWith("set_display_name", { name: "Grandma" });
    expect(invoke).toHaveBeenCalledWith("set_chat_enabled", { enabled: true });
    expect(calls.indexOf("set_display_name")).toBeLessThan(calls.indexOf("set_chat_enabled"));
    expect(calls.indexOf("set_chat_enabled")).toBeLessThan(calls.indexOf("set_onboarding_done"));
    expect(onChatStart).toHaveBeenCalledTimes(1);
  });

  it("Start does not hand off to chat when the resolved flag is false", async () => {
    (invoke as InvokeMock).mockImplementation((cmd: string) => {
      if (cmd === "onboarding_done") return Promise.resolve(false);
      if (cmd === "set_chat_enabled") return Promise.resolve(false);
      return Promise.resolve(null);
    });
    const onChatStart = vi.fn();
    const h = host();
    await initOnboarding(h, { onChatStart });
    const input = h.querySelector<HTMLInputElement>(".onboarding__name")!;
    input.value = "Grandma";
    input.dispatchEvent(new Event("input"));
    h.querySelector<HTMLButtonElement>(".onboarding__start")!.click();
    await vi.waitFor(() => expect(h.hidden).toBe(true));
    expect(onChatStart).not.toHaveBeenCalled();
  });

  it("Skip marks done and touches nothing else", async () => {
    (invoke as InvokeMock).mockImplementation((cmd: string) =>
      Promise.resolve(cmd === "onboarding_done" ? false : null),
    );
    const onChatStart = vi.fn();
    const h = host();
    await initOnboarding(h, { onChatStart });
    h.querySelector<HTMLButtonElement>(".onboarding__skip")!.click();
    await vi.waitFor(() => expect(h.hidden).toBe(true));
    expect(invoke).toHaveBeenCalledWith("set_onboarding_done");
    expect(invoke).not.toHaveBeenCalledWith("set_display_name", expect.anything());
    expect(invoke).not.toHaveBeenCalledWith("set_chat_enabled", expect.anything());
    expect(onChatStart).not.toHaveBeenCalled();
  });

  it("completes onboarding even when the start sequence fails", async () => {
    (invoke as InvokeMock).mockImplementation((cmd: string) => {
      if (cmd === "onboarding_done") return Promise.resolve(false);
      if (cmd === "set_display_name") return Promise.reject(new Error("boom"));
      return Promise.resolve(null);
    });
    const onChatStart = vi.fn();
    const h = host();
    await initOnboarding(h, { onChatStart });
    const input = h.querySelector<HTMLInputElement>(".onboarding__name")!;
    input.value = "Grandma";
    input.dispatchEvent(new Event("input"));
    h.querySelector<HTMLButtonElement>(".onboarding__start")!.click();
    await vi.waitFor(() => expect(h.hidden).toBe(true));
    expect(invoke).toHaveBeenCalledWith("set_onboarding_done");
    expect(onChatStart).not.toHaveBeenCalled();
  });

  it("restore link swaps to phrase entry, gates on 24 words, restores, restarts", async () => {
    vi.useFakeTimers();
    (invoke as InvokeMock).mockImplementation((cmd: string) => {
      if (cmd === "onboarding_done") return Promise.resolve(false);
      if (cmd === "chat_restore_recovery_phrase") return Promise.resolve("ab".repeat(32));
      return Promise.resolve(null);
    });
    const h = host();
    await initOnboarding(h, { onChatStart: vi.fn() });
    h.querySelector<HTMLButtonElement>(".onboarding__restore-link")!.click();

    const phrase = h.querySelector<HTMLTextAreaElement>(".onboarding__phrase")!;
    const go = h.querySelector<HTMLButtonElement>(".onboarding__restore .onboarding__start")!;
    // 23 words: still disabled. 24: enabled.
    phrase.value = Array(23).fill("word").join(" ");
    phrase.dispatchEvent(new Event("input"));
    expect(go.disabled).toBe(true);
    phrase.value = Array(24).fill("word").join(" ");
    phrase.dispatchEvent(new Event("input"));
    expect(go.disabled).toBe(false);

    go.click();
    await vi.waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("chat_restore_recovery_phrase", {
        phrase: Array(24).fill("word").join(" "),
      }),
    );
    await vi.advanceTimersByTimeAsync(1000);
    expect(invoke).toHaveBeenCalledWith("restart_app");
    vi.useRealTimers();
  });

  it("a rejected restore shows the error and does not restart", async () => {
    vi.useFakeTimers();
    (invoke as InvokeMock).mockImplementation((cmd: string) => {
      if (cmd === "onboarding_done") return Promise.resolve(false);
      if (cmd === "chat_restore_recovery_phrase") {
        return Promise.reject(new Error("that phrase has a typo — check word 7"));
      }
      return Promise.resolve(null);
    });
    const h = host();
    await initOnboarding(h, { onChatStart: vi.fn() });
    h.querySelector<HTMLButtonElement>(".onboarding__restore-link")!.click();
    const phrase = h.querySelector<HTMLTextAreaElement>(".onboarding__phrase")!;
    phrase.value = Array(24).fill("word").join(" ");
    phrase.dispatchEvent(new Event("input"));
    h.querySelector<HTMLButtonElement>(".onboarding__restore .onboarding__start")!.click();

    await vi.waitFor(() => {
      const err = h.querySelector<HTMLParagraphElement>(".onboarding__error")!;
      expect(err.hidden).toBe(false);
      expect(err.textContent).toContain("typo");
    });
    await vi.advanceTimersByTimeAsync(1000);
    expect(invoke).not.toHaveBeenCalledWith("restart_app");
    vi.useRealTimers();
  });

  it("Back returns from restore mode to the name form", async () => {
    (invoke as InvokeMock).mockResolvedValue(false);
    const h = host();
    await initOnboarding(h, { onChatStart: vi.fn() });
    h.querySelector<HTMLButtonElement>(".onboarding__restore-link")!.click();
    expect(h.querySelector(".onboarding__restore")).not.toBeNull();
    h.querySelector<HTMLButtonElement>(".onboarding__restore .onboarding__skip")!.click();
    expect(h.querySelector(".onboarding__restore")).toBeNull();
    const name = h.querySelector<HTMLInputElement>(".onboarding__name")!;
    expect(name.hidden).toBe(false);
  });

  it("exports the locked copy object", () => {
    expect(ONBOARDING_COPY.title).toBe("Welcome to fetch>it");
    expect(ONBOARDING_COPY.question).toBe("What should we call you?");
    expect(ONBOARDING_COPY.start).toBe("Start");
    expect(ONBOARDING_COPY.skip).toBe("Skip for now");
  });
});
