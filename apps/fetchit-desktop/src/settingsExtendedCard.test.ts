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

describe("settingsExtendedCard — Advanced demotion of the v2 share URI", () => {
  it("is described as the offline / fallback path", () => {
    expect(EXTENDED_CARD_HTML).toMatch(/offline|fallback/i);
  });

  it("generates the v2 extended URI via chat_card and renders it copyable", async () => {
    invokeMock.mockResolvedValueOnce({
      card: { agent_id: "ab".repeat(32), display_name: "Alice" },
      uri: "x0x://agent/" + "Z".repeat(2000),
    });
    initExtendedCardPanel(root);

    genBtn().click();
    await Promise.resolve();
    await Promise.resolve();

    expect(invokeMock).toHaveBeenCalledWith("chat_card", { displayName: "" });
    expect(uriBox().value).toContain("x0x://agent/");
  });

  it("renders an honest error when the daemon rejects card generation", async () => {
    invokeMock.mockRejectedValueOnce("chat feature disabled");
    initExtendedCardPanel(root);

    genBtn().click();
    await Promise.resolve();
    await Promise.resolve();

    const err = root.querySelector<HTMLElement>(`#${EXTENDED_CARD_IDS.error}`)!;
    expect(err.hidden).toBe(false);
    expect(err.textContent ?? "").toContain("chat feature disabled");
  });

  it("is idempotent — re-init on the same root does not double-bind", async () => {
    invokeMock.mockResolvedValue({
      card: { agent_id: "ab".repeat(32), display_name: "Alice" },
      uri: "x0x://agent/extended",
    });
    initExtendedCardPanel(root);
    initExtendedCardPanel(root);

    genBtn().click();
    await Promise.resolve();
    await Promise.resolve();

    const cardCalls = invokeMock.mock.calls.filter(([cmd]) => cmd === "chat_card");
    expect(cardCalls).toHaveLength(1);
  });
});
