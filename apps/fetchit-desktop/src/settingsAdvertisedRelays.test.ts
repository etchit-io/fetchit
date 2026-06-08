import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

// eslint-disable-next-line import/first
import { invoke } from "@tauri-apps/api/core";
// eslint-disable-next-line import/first
import {
  ADVERTISED_RELAYS_HTML,
  ADVERTISED_RELAYS_IDS,
  initAdvertisedRelaysPanel,
} from "./settingsAdvertisedRelays";

type InvokeMock = ReturnType<typeof vi.fn>;

function mountPanel(): HTMLDivElement {
  const root = document.createElement("div");
  // ADVERTISED_RELAYS_HTML is a module-level constant containing only
  // static markup; no user input or runtime data is interpolated. The
  // production integration path also injects this string via the
  // settings.ts template (the established frontend rendering pattern),
  // so testing here through the same channel is the truthful mount.
  // Not an XSS surface: the constant ships in the bundle.
  root.innerHTML = ADVERTISED_RELAYS_HTML;
  document.body.append(root);
  initAdvertisedRelaysPanel(root);
  return root;
}

beforeEach(() => {
  (invoke as InvokeMock).mockReset();
  document.body.innerHTML = "";
});

afterEach(() => {
  document.body.innerHTML = "";
});

describe("settingsAdvertisedRelays", () => {
  it("starts with no relay rows visible", () => {
    const root = mountPanel();
    const rows = root.querySelectorAll(".advertised-relays-row");
    expect(rows).toHaveLength(0);
  });

  it("appends an editable row on +Add relay click", () => {
    const root = mountPanel();
    const addBtn = root.querySelector<HTMLButtonElement>(`#${ADVERTISED_RELAYS_IDS.add}`);
    expect(addBtn).not.toBeNull();
    addBtn!.click();
    addBtn!.click();
    const inputs = root.querySelectorAll<HTMLInputElement>(
      `#${ADVERTISED_RELAYS_IDS.list} input`,
    );
    expect(inputs).toHaveLength(2);
  });

  it("removes a row when its Remove button is clicked", () => {
    const root = mountPanel();
    const addBtn = root.querySelector<HTMLButtonElement>(`#${ADVERTISED_RELAYS_IDS.add}`);
    addBtn!.click();
    addBtn!.click();
    const rows = root.querySelectorAll<HTMLDivElement>(".advertised-relays-row");
    expect(rows).toHaveLength(2);
    const firstRemove = rows[0].querySelector<HTMLButtonElement>("button");
    firstRemove!.click();
    expect(root.querySelectorAll(".advertised-relays-row")).toHaveLength(1);
  });

  it("invokes chat_regenerate_card_with_relays with trimmed non-empty values on Save", async () => {
    (invoke as InvokeMock).mockResolvedValueOnce(undefined);
    const root = mountPanel();
    const addBtn = root.querySelector<HTMLButtonElement>(`#${ADVERTISED_RELAYS_IDS.add}`);
    addBtn!.click();
    addBtn!.click();
    addBtn!.click();
    const inputs = root.querySelectorAll<HTMLInputElement>(
      `#${ADVERTISED_RELAYS_IDS.list} input`,
    );
    inputs[0].value = " wss://nyc.example/v1/ws ";
    inputs[1].value = "";
    inputs[2].value = "wss://fra.example/v1/ws";
    const saveBtn = root.querySelector<HTMLButtonElement>(`#${ADVERTISED_RELAYS_IDS.save}`);
    saveBtn!.click();
    await vi.waitFor(() => {
      expect((invoke as InvokeMock).mock.calls.length).toBeGreaterThan(0);
    });
    const [cmd, args] = (invoke as InvokeMock).mock.calls[0];
    expect(cmd).toBe("chat_regenerate_card_with_relays");
    expect(args).toEqual({
      relays: ["wss://nyc.example/v1/ws", "wss://fra.example/v1/ws"],
    });
    const status = root.querySelector<HTMLParagraphElement>(
      `#${ADVERTISED_RELAYS_IDS.status}`,
    );
    expect(status?.hidden).toBe(false);
    expect(status?.textContent).toContain("2 relays");
  });

  it("surfaces invoke errors in the error slot", async () => {
    (invoke as InvokeMock).mockRejectedValueOnce(
      "relays list rejected: non-wss scheme",
    );
    const root = mountPanel();
    const addBtn = root.querySelector<HTMLButtonElement>(`#${ADVERTISED_RELAYS_IDS.add}`);
    addBtn!.click();
    const input = root.querySelector<HTMLInputElement>(
      `#${ADVERTISED_RELAYS_IDS.list} input`,
    );
    input!.value = "http://not-wss.example";
    const saveBtn = root.querySelector<HTMLButtonElement>(`#${ADVERTISED_RELAYS_IDS.save}`);
    saveBtn!.click();
    await vi.waitFor(() => {
      const err = root.querySelector<HTMLParagraphElement>(
        `#${ADVERTISED_RELAYS_IDS.error}`,
      );
      expect(err?.hidden).toBe(false);
      expect(err?.textContent).toContain("non-wss scheme");
    });
    const status = root.querySelector<HTMLParagraphElement>(
      `#${ADVERTISED_RELAYS_IDS.status}`,
    );
    expect(status?.hidden).toBe(true);
  });

  it("treats Save with all-empty rows as an empty list (relays: [])", async () => {
    (invoke as InvokeMock).mockResolvedValueOnce(undefined);
    const root = mountPanel();
    const addBtn = root.querySelector<HTMLButtonElement>(`#${ADVERTISED_RELAYS_IDS.add}`);
    addBtn!.click();
    addBtn!.click();
    const saveBtn = root.querySelector<HTMLButtonElement>(`#${ADVERTISED_RELAYS_IDS.save}`);
    saveBtn!.click();
    await vi.waitFor(() => {
      expect((invoke as InvokeMock).mock.calls.length).toBeGreaterThan(0);
    });
    expect((invoke as InvokeMock).mock.calls[0][1]).toEqual({ relays: [] });
  });

  it("re-init on an already-bound root is a no-op (no duplicate handlers)", () => {
    const root = mountPanel();
    initAdvertisedRelaysPanel(root);
    initAdvertisedRelaysPanel(root);
    const addBtn = root.querySelector<HTMLButtonElement>(`#${ADVERTISED_RELAYS_IDS.add}`);
    addBtn!.click();
    const rows = root.querySelectorAll<HTMLDivElement>(".advertised-relays-row");
    expect(rows).toHaveLength(1);
  });
});
