import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

// eslint-disable-next-line import/first
import { invoke } from "@tauri-apps/api/core";
// eslint-disable-next-line import/first
import {
  CUSTODY_COPY,
  CUSTODY_IDS,
  CUSTODY_PANEL_HTML,
  initCustodyPanel,
} from "./settingsCustody";

type InvokeMock = ReturnType<typeof vi.fn>;

function mount(): HTMLElement {
  const root = document.createElement("div");
  root.innerHTML = CUSTODY_PANEL_HTML;
  document.body.append(root);
  return root;
}

beforeEach(() => {
  (invoke as InvokeMock).mockReset();
  document.body.innerHTML = "";
});

describe("custody panel", () => {
  it("shows the current mode from chat_custody_status", async () => {
    (invoke as InvokeMock).mockResolvedValue("keychain");
    const root = mount();
    initCustodyPanel(root);
    await vi.waitFor(() => {
      expect(root.querySelector(`#${CUSTODY_IDS.status}`)?.textContent).toContain(
        "system keychain",
      );
    });
  });

  it("applying a passphrase calls chat_rekey_vault with it", async () => {
    (invoke as InvokeMock).mockResolvedValue("keychain");
    const root = mount();
    initCustodyPanel(root);
    const pass = root.querySelector<HTMLInputElement>(`#${CUSTODY_IDS.passphrase}`)!;
    pass.value = "hunter2";
    root.querySelector<HTMLButtonElement>(`#${CUSTODY_IDS.toPassphrase}`)!.click();
    await vi.waitFor(() => {
      expect(invoke).toHaveBeenCalledWith("chat_rekey_vault", {
        newPassphrase: "hunter2",
      });
    });
  });

  it("blocks a blank passphrase client-side", async () => {
    (invoke as InvokeMock).mockResolvedValue("keychain");
    const root = mount();
    initCustodyPanel(root);
    root.querySelector<HTMLButtonElement>(`#${CUSTODY_IDS.toPassphrase}`)!.click();
    await Promise.resolve();
    expect(invoke).not.toHaveBeenCalledWith("chat_rekey_vault", expect.anything());
    expect(root.querySelector(`#${CUSTODY_IDS.error}`)?.textContent).not.toBe("");
  });

  it("returning to keychain calls chat_rekey_vault with null", async () => {
    (invoke as InvokeMock).mockResolvedValue("passphrase");
    const root = mount();
    initCustodyPanel(root);
    root.querySelector<HTMLButtonElement>(`#${CUSTODY_IDS.toKeychain}`)!.click();
    await vi.waitFor(() => {
      expect(invoke).toHaveBeenCalledWith("chat_rekey_vault", { newPassphrase: null });
    });
  });

  it("surfaces a rekey failure without clearing the input", async () => {
    (invoke as InvokeMock).mockImplementation((cmd: string) =>
      cmd === "chat_rekey_vault"
        ? Promise.reject(new Error("keystore unreachable"))
        : Promise.resolve("keychain"),
    );
    const root = mount();
    initCustodyPanel(root);
    const pass = root.querySelector<HTMLInputElement>(`#${CUSTODY_IDS.passphrase}`)!;
    pass.value = "hunter2";
    root.querySelector<HTMLButtonElement>(`#${CUSTODY_IDS.toPassphrase}`)!.click();
    await vi.waitFor(() => {
      expect(root.querySelector(`#${CUSTODY_IDS.error}`)?.textContent).toContain(
        "keystore unreachable",
      );
    });
    expect(pass.value).toBe("hunter2");
  });

  it("carries the specific risk copy in the template", () => {
    expect(CUSTODY_COPY.risk).toContain("can't be recovered");
    expect(CUSTODY_PANEL_HTML).toContain(CUSTODY_COPY.risk);
  });
});
