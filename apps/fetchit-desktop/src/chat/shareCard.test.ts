import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const pairShareUriMock = vi.fn<() => Promise<string>>();

vi.mock("./api", () => ({
  pairShareUri: () => pairShareUriMock(),
}));

import { mountShareCard } from "./shareCard";

const POINTER_URI
  = "x0x://pair/" + "ab".repeat(32) + "?r=https%3A%2F%2Frelay.example";

let host: HTMLElement;

beforeEach(() => {
  pairShareUriMock.mockReset();
  host = document.createElement("div");
  document.body.appendChild(host);
});

afterEach(() => {
  host.remove();
});

function getStatus(): HTMLElement {
  return host.querySelector<HTMLElement>(".chat-dialog__status")!;
}

function getUriBox(): HTMLTextAreaElement {
  return host.querySelector<HTMLTextAreaElement>(".chat-dialog__uri")!;
}

function getQrHost(): HTMLElement {
  return host.querySelector<HTMLElement>(".chat-dialog__qr")!;
}

describe("mountShareCard", () => {
  it("shows a Publishing state until the pointer URI resolves", async () => {
    let resolveShare: ((uri: string) => void) | undefined;
    pairShareUriMock.mockImplementationOnce(
      () =>
        new Promise<string>((resolve) => {
          resolveShare = resolve;
        }),
    );
    mountShareCard(host, { onClose: () => {} });

    // Before the invoke resolves the dialog must announce it is
    // publishing the reachability record (so a shared URI never 404s).
    expect(getStatus().textContent).toMatch(/Publishing/i);
    expect(getUriBox().value).toBe("");

    resolveShare?.(POINTER_URI);
    await Promise.resolve();
    await Promise.resolve();
  });

  it("renders the short pointer URI as copyable text and a QR on success", async () => {
    pairShareUriMock.mockResolvedValueOnce(POINTER_URI);
    mountShareCard(host, { onClose: () => {} });
    await Promise.resolve();
    await Promise.resolve();

    expect(getUriBox().value).toBe(POINTER_URI);
    // A QR svg is painted (qr.ts renders an <svg role="img">).
    expect(getQrHost().querySelector("svg")).not.toBeNull();
    // The pointer URI is short enough to never trip the v2 "too large
    // for a QR" fallback.
    expect(getQrHost().textContent ?? "").not.toContain("too large");
  });

  it("copies the pointer URI to the clipboard on Copy", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });
    pairShareUriMock.mockResolvedValueOnce(POINTER_URI);
    mountShareCard(host, { onClose: () => {} });
    await Promise.resolve();
    await Promise.resolve();

    const copyBtn = host.querySelector<HTMLButtonElement>(".chat-dialog__btn")!;
    copyBtn.click();
    await Promise.resolve();
    expect(writeText).toHaveBeenCalledWith(POINTER_URI);
  });

  it("shows an honest offline error when publishing fails", async () => {
    pairShareUriMock.mockRejectedValueOnce(new Error("relay unreachable"));
    mountShareCard(host, { onClose: () => {} });
    await Promise.resolve();
    await Promise.resolve();

    const status = getStatus().textContent ?? "";
    // Honest, plain-English copy: the user is offline / the relay is
    // unreachable, so the URI can't be shared safely.
    expect(status).toMatch(/offline|couldn't|could not|reach/i);
    // No QR or URI is shown for a record that didn't publish.
    expect(getUriBox().value).toBe("");
  });

  it("does not write to detached nodes when the dialog closes before resolve", async () => {
    let resolveShare: ((uri: string) => void) | undefined;
    pairShareUriMock.mockImplementationOnce(
      () =>
        new Promise<string>((resolve) => {
          resolveShare = resolve;
        }),
    );
    mountShareCard(host, { onClose: () => {} });

    // Capture the dialog's children, then close the dialog the way panel.ts
    // hideDialog does (replaceChildren detaches `inner`).
    const status = getStatus();
    const uriBox = getUriBox();
    const copyBtn = host.querySelector<HTMLButtonElement>(".chat-dialog__btn")!;
    const qrHost = getQrHost();
    expect(status.textContent).toMatch(/Publishing/i);
    host.replaceChildren();

    // Resolving the pending publish must not throw nor write to the now
    // detached nodes: the guard bails on !inner.isConnected.
    resolveShare?.(POINTER_URI);
    await Promise.resolve();
    await Promise.resolve();

    expect(status.textContent).toMatch(/Publishing/i);
    expect(uriBox.value).toBe("");
    expect(copyBtn.disabled).toBe(true);
    expect(qrHost.querySelector("svg")).toBeNull();
  });

  it("falls back to execCommand copy when clipboard writeText rejects", async () => {
    const writeText = vi.fn().mockRejectedValue(new Error("denied"));
    Object.assign(navigator, { clipboard: { writeText } });
    const execCommand = vi.fn().mockReturnValue(true);
    Object.assign(document, { execCommand });
    pairShareUriMock.mockResolvedValueOnce(POINTER_URI);
    mountShareCard(host, { onClose: () => {} });
    await Promise.resolve();
    await Promise.resolve();

    const copyBtn = host.querySelector<HTMLButtonElement>(".chat-dialog__btn")!;
    copyBtn.click();
    await Promise.resolve();
    await Promise.resolve();

    expect(writeText).toHaveBeenCalled();
    expect(execCommand).toHaveBeenCalledWith("copy");
  });

  it("invokes onClose for Cancel and the backdrop", async () => {
    pairShareUriMock.mockResolvedValueOnce(POINTER_URI);
    const onClose = vi.fn();
    mountShareCard(host, { onClose });
    await Promise.resolve();

    const closeBtn = host.querySelectorAll<HTMLButtonElement>(".chat-dialog__btn")[1];
    closeBtn.click();
    expect(onClose).toHaveBeenCalledTimes(1);

    host.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(onClose).toHaveBeenCalledTimes(2);
  });
});
