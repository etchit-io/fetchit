import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mountAddContact } from "./addContact";

const importCardMock = vi.fn<(uri: string) => Promise<void>>();

vi.mock("./api", () => ({
  importCard: (uri: string) => importCardMock(uri),
}));

const VALID = "x0x://agent/abcdefghijklmnop";

let host: HTMLElement;

beforeEach(() => {
  importCardMock.mockReset();
  host = document.createElement("div");
  document.body.appendChild(host);
});

afterEach(() => {
  host.remove();
});

function getInput(): HTMLTextAreaElement {
  return host.querySelector<HTMLTextAreaElement>(".chat-dialog__uri")!;
}

function getAddBtn(): HTMLButtonElement {
  return host.querySelector<HTMLButtonElement>(".chat-dialog__btn")!;
}

function getStatus(): HTMLElement {
  return host.querySelector<HTMLElement>(".chat-dialog__status")!;
}

describe("mountAddContact", () => {
  it("only enables Add once the trimmed value starts with x0x://agent/", () => {
    mountAddContact(host, { onClose: () => {}, onImported: () => {} });
    const btn = getAddBtn();
    const input = getInput();

    expect(btn.disabled).toBe(true);

    input.value = "hello world";
    input.dispatchEvent(new Event("input"));
    expect(btn.disabled).toBe(true);

    input.value = "x0x://invite/abcdefghijklmnop";
    input.dispatchEvent(new Event("input"));
    expect(btn.disabled).toBe(true);

    input.value = "x0x://group/abcdefghijklmnop";
    input.dispatchEvent(new Event("input"));
    expect(btn.disabled).toBe(true);

    input.value = VALID;
    input.dispatchEvent(new Event("input"));
    expect(btn.disabled).toBe(false);
  });

  it("accepts a card URI with surrounding whitespace", () => {
    mountAddContact(host, { onClose: () => {}, onImported: () => {} });
    const input = getInput();
    const btn = getAddBtn();

    input.value = `   \n${VALID}\t  `;
    input.dispatchEvent(new Event("input"));
    expect(btn.disabled).toBe(false);
  });

  it("returns to disabled and clears status when the textarea is emptied", () => {
    mountAddContact(host, { onClose: () => {}, onImported: () => {} });
    const input = getInput();
    const btn = getAddBtn();
    const status = getStatus();

    input.value = VALID;
    input.dispatchEvent(new Event("input"));
    expect(btn.disabled).toBe(false);

    status.textContent = "stale";
    input.value = "";
    input.dispatchEvent(new Event("input"));
    expect(btn.disabled).toBe(true);
    expect(status.textContent).toBe("");
  });

  it("forwards the trimmed URI to importCard on submit", async () => {
    importCardMock.mockResolvedValueOnce(undefined);
    mountAddContact(host, { onClose: () => {}, onImported: () => {} });
    const input = getInput();
    const btn = getAddBtn();

    input.value = `  ${VALID}\n`;
    input.dispatchEvent(new Event("input"));
    btn.click();
    await Promise.resolve();
    await Promise.resolve();

    expect(importCardMock).toHaveBeenCalledWith(VALID);
    expect(getStatus().textContent).toBe("Imported.");
  });

  it("invokes onImported exactly once on success", async () => {
    importCardMock.mockResolvedValueOnce(undefined);
    const onImported = vi.fn();
    mountAddContact(host, { onClose: () => {}, onImported });
    const input = getInput();
    const btn = getAddBtn();

    input.value = VALID;
    input.dispatchEvent(new Event("input"));
    btn.click();
    await Promise.resolve();
    await Promise.resolve();

    expect(onImported).toHaveBeenCalledTimes(1);
  });

  it("renders Error messages and re-enables Add on failure", async () => {
    importCardMock.mockRejectedValueOnce(new Error("bad card"));
    const onImported = vi.fn();
    mountAddContact(host, { onClose: () => {}, onImported });
    const input = getInput();
    const btn = getAddBtn();

    input.value = VALID;
    input.dispatchEvent(new Event("input"));
    btn.click();
    await Promise.resolve();
    await Promise.resolve();

    expect(getStatus().textContent).toContain("bad card");
    expect(btn.disabled).toBe(false);
    expect(onImported).not.toHaveBeenCalled();
  });

  it("renders bare-string rejections from Tauri verbatim", async () => {
    importCardMock.mockRejectedValueOnce("daemon offline");
    mountAddContact(host, { onClose: () => {}, onImported: () => {} });
    const input = getInput();
    const btn = getAddBtn();

    input.value = VALID;
    input.dispatchEvent(new Event("input"));
    btn.click();
    await Promise.resolve();
    await Promise.resolve();

    const status = getStatus().textContent ?? "";
    expect(status).toContain("daemon offline");
    expect(status).not.toContain("undefined");
  });

  it("locks Add while an import is in flight", async () => {
    let resolveImport: (() => void) | undefined;
    importCardMock.mockImplementationOnce(
      () =>
        new Promise<void>((resolve) => {
          resolveImport = resolve;
        }),
    );
    mountAddContact(host, { onClose: () => {}, onImported: () => {} });
    const input = getInput();
    const btn = getAddBtn();

    input.value = VALID;
    input.dispatchEvent(new Event("input"));
    btn.click();
    await Promise.resolve();

    expect(btn.disabled).toBe(true);
    expect(getStatus().textContent).toBe("Importing…");

    resolveImport?.();
  });

  it("invokes onClose for Cancel and backdrop, but not for panel clicks", () => {
    const onClose = vi.fn();
    mountAddContact(host, { onClose, onImported: () => {} });

    const cancelBtn = host.querySelectorAll<HTMLButtonElement>(
      ".chat-dialog__btn",
    )[1];
    cancelBtn.click();
    expect(onClose).toHaveBeenCalledTimes(1);

    host.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(onClose).toHaveBeenCalledTimes(2);

    const panel = host.querySelector<HTMLElement>(".chat-dialog__panel")!;
    panel.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(onClose).toHaveBeenCalledTimes(2);
  });

  it("uses a multi-row textarea with the Card URI aria-label", () => {
    mountAddContact(host, { onClose: () => {}, onImported: () => {} });
    const input = getInput();
    expect(input.tagName).toBe("TEXTAREA");
    expect(input.rows).toBeGreaterThanOrEqual(2);
    expect(input.getAttribute("aria-label")).toBe("Card URI");
  });
});
