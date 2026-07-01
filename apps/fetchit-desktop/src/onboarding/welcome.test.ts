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
    expect(h.textContent).toContain(
      "Your chat keys are created on this device and stay only here. "
        + "If you switch computers you start fresh, and add your people "
        + "again with a QR code. Nothing about you is stored in any cloud.",
    );
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

  it("exports the locked copy object", () => {
    expect(ONBOARDING_COPY.title).toBe("Welcome to fetch>it");
    expect(ONBOARDING_COPY.question).toBe("What should we call you?");
    expect(ONBOARDING_COPY.start).toBe("Start");
    expect(ONBOARDING_COPY.skip).toBe("Skip for now");
  });
});
