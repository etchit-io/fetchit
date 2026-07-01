import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

// eslint-disable-next-line import/first
import { invoke } from "@tauri-apps/api/core";
// eslint-disable-next-line import/first
import {
  BACKUP_COPY,
  BACKUP_IDS,
  BACKUP_PANEL_HTML,
  initBackupPanel,
} from "./settingsBackup";

type InvokeMock = ReturnType<typeof vi.fn>;

const PHRASE = Array.from({ length: 24 }, (_, i) => `word${i + 1}`).join(" ");

function mount(): HTMLElement {
  document.body.innerHTML = `<div id="root">${BACKUP_PANEL_HTML}</div>`;
  const root = document.body.querySelector<HTMLElement>("#root")!;
  initBackupPanel(root);
  return root;
}

beforeEach(() => {
  (invoke as InvokeMock).mockReset();
});

describe("initBackupPanel", () => {
  it("first click arms with the shoulder-surfing warning, no reveal yet", () => {
    const root = mount();
    root.querySelector<HTMLButtonElement>(`#${BACKUP_IDS.reveal}`)!.click();
    expect(invoke).not.toHaveBeenCalled();
    expect(root.querySelector(`#${BACKUP_IDS.intro}`)!.textContent).toBe(BACKUP_COPY.confirm);
    expect(root.querySelector(`#${BACKUP_IDS.reveal}`)!.textContent).toBe(
      BACKUP_COPY.confirmReveal,
    );
  });

  it("second click reveals the 24 words as a numbered list", async () => {
    (invoke as InvokeMock).mockResolvedValue(PHRASE);
    const root = mount();
    const reveal = root.querySelector<HTMLButtonElement>(`#${BACKUP_IDS.reveal}`)!;
    reveal.click();
    reveal.click();
    await vi.waitFor(() => {
      const items = root.querySelectorAll(`#${BACKUP_IDS.words} li`);
      expect(items).toHaveLength(24);
      expect(items[0].textContent).toBe("word1");
      expect(items[23].textContent).toBe("word24");
    });
    expect(invoke).toHaveBeenCalledWith("chat_reveal_recovery_phrase");
    expect(root.querySelector<HTMLElement>(`#${BACKUP_IDS.note}`)!.hidden).toBe(false);
    expect(reveal.hidden).toBe(true);
  });

  it("hide clears the words from the DOM entirely", async () => {
    (invoke as InvokeMock).mockResolvedValue(PHRASE);
    const root = mount();
    const reveal = root.querySelector<HTMLButtonElement>(`#${BACKUP_IDS.reveal}`)!;
    reveal.click();
    reveal.click();
    await vi.waitFor(() =>
      expect(root.querySelectorAll(`#${BACKUP_IDS.words} li`)).toHaveLength(24),
    );
    root.querySelector<HTMLButtonElement>(`#${BACKUP_IDS.hide}`)!.click();
    // The secret must not linger in the DOM once hidden.
    expect(root.querySelectorAll(`#${BACKUP_IDS.words} li`)).toHaveLength(0);
    expect(root.textContent).not.toContain("word1");
    expect(reveal.hidden).toBe(false);
    expect(root.querySelector(`#${BACKUP_IDS.intro}`)!.textContent).toBe(BACKUP_COPY.intro);
  });

  it("a legacy identity (null phrase) explains itself instead of erroring", async () => {
    (invoke as InvokeMock).mockResolvedValue(null);
    const root = mount();
    const reveal = root.querySelector<HTMLButtonElement>(`#${BACKUP_IDS.reveal}`)!;
    reveal.click();
    reveal.click();
    await vi.waitFor(() =>
      expect(root.querySelector(`#${BACKUP_IDS.intro}`)!.textContent).toBe(BACKUP_COPY.legacy),
    );
    expect(root.querySelectorAll(`#${BACKUP_IDS.words} li`)).toHaveLength(0);
    expect(root.querySelector<HTMLElement>(`#${BACKUP_IDS.error}`)!.hidden).toBe(true);
  });

  it("a failed reveal surfaces the error", async () => {
    (invoke as InvokeMock).mockRejectedValue(new Error("vault locked"));
    const root = mount();
    const reveal = root.querySelector<HTMLButtonElement>(`#${BACKUP_IDS.reveal}`)!;
    reveal.click();
    reveal.click();
    await vi.waitFor(() => {
      const err = root.querySelector<HTMLElement>(`#${BACKUP_IDS.error}`)!;
      expect(err.hidden).toBe(false);
      expect(err.textContent).toContain("vault locked");
    });
  });

  it("re-init on the same root does not double-bind the reveal handler", () => {
    const root = mount();
    initBackupPanel(root);
    root.querySelector<HTMLButtonElement>(`#${BACKUP_IDS.reveal}`)!.click();
    // A double-bound handler would arm then immediately fire the armed
    // branch, invoking the backend on the first click.
    expect(invoke).not.toHaveBeenCalled();
  });
});
