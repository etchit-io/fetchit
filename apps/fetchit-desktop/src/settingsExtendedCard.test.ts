import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const invokeMock = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (cmd: string, args?: unknown) => invokeMock(cmd, args),
}));

import {
  EXTENDED_CARD_HTML,
  EXTENDED_CARD_IDS,
  initExtendedCardPanel,
} from "./settingsExtendedCard";

let root: HTMLElement;

beforeEach(() => {
  invokeMock.mockReset();
  root = document.createElement("div");
  root.innerHTML = EXTENDED_CARD_HTML;
  document.body.appendChild(root);
});

afterEach(() => {
  root.remove();
});

function genBtn(): HTMLButtonElement {
  return root.querySelector<HTMLButtonElement>(`#${EXTENDED_CARD_IDS.generate}`)!;
}

function uriBox(): HTMLTextAreaElement {
  return root.querySelector<HTMLTextAreaElement>(`#${EXTENDED_CARD_IDS.uri}`)!;
}

async function flushAsync(): Promise<void> {
  for (let i = 0; i < 8; i += 1) {
    await Promise.resolve();
  }
}

/// Command-aware invoke stub: the generate flow first reads the stored
/// display name, then asks the daemon for the card.
function mockDaemon(opts: {
  displayName?: string | Error;
  card?: { uri: string } | Error;
}): void {
  invokeMock.mockImplementation((cmd: string) => {
    if (cmd === "display_name") {
      const v = opts.displayName ?? "";
      return v instanceof Error ? Promise.reject(v) : Promise.resolve(v);
    }
    if (cmd === "chat_card") {
      const v = opts.card ?? new Error("no card stubbed");
      return v instanceof Error
        ? Promise.reject(v.message)
        : Promise.resolve({
            card: { agent_id: "ab".repeat(32), display_name: "Alice" },
            uri: v.uri,
          });
    }
    return Promise.reject(new Error(`unexpected command: ${cmd}`));
  });
}

describe("settingsExtendedCard — Advanced demotion of the v2 share URI", () => {
  it("is described as the offline / fallback path", () => {
    expect(EXTENDED_CARD_HTML).toMatch(/offline|fallback/i);
  });

  it("generates the v2 extended URI via chat_card and renders it copyable", async () => {
    mockDaemon({
      displayName: "Alice",
      card: { uri: "x0x://agent/" + "Z".repeat(2000) },
    });
    initExtendedCardPanel(root);

    genBtn().click();
    await flushAsync();

    // The daemon stamps the supplied name into the card verbatim, so
    // the panel must pass the stored display name, not an empty string.
    expect(invokeMock).toHaveBeenCalledWith("chat_card", { displayName: "Alice" });
    expect(uriBox().value).toContain("x0x://agent/");
  });

  it("degrades to a nameless card when the display name can't be read", async () => {
    mockDaemon({
      displayName: new Error("settings unavailable"),
      card: { uri: "x0x://agent/extended" },
    });
    initExtendedCardPanel(root);

    genBtn().click();
    await flushAsync();

    expect(invokeMock).toHaveBeenCalledWith("chat_card", { displayName: "" });
    expect(uriBox().value).toContain("x0x://agent/");
  });

  it("renders an honest error when the daemon rejects card generation", async () => {
    mockDaemon({
      displayName: "Alice",
      card: new Error("chat feature disabled"),
    });
    initExtendedCardPanel(root);

    genBtn().click();
    await flushAsync();

    const err = root.querySelector<HTMLElement>(`#${EXTENDED_CARD_IDS.error}`)!;
    expect(err.hidden).toBe(false);
    expect(err.textContent ?? "").toContain("chat feature disabled");
  });

  it("is idempotent — re-init on the same root does not double-bind", async () => {
    mockDaemon({
      displayName: "Alice",
      card: { uri: "x0x://agent/extended" },
    });
    initExtendedCardPanel(root);
    initExtendedCardPanel(root);

    genBtn().click();
    await flushAsync();

    const cardCalls = invokeMock.mock.calls.filter(([cmd]) => cmd === "chat_card");
    expect(cardCalls).toHaveLength(1);
  });
});
