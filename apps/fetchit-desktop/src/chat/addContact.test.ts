import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mountAddContact } from "./addContact";

const importCardMock = vi.fn<(uri: string) => Promise<void>>();
const pairAcceptMock = vi.fn<
  (uri: string) => Promise<{
    agentIdHex: string;
    offererRelayUrl?: string;
    crossRelay?: boolean;
  }>
>();
const importPairUriMock = vi.fn<(uri: string) => Promise<void>>();
const lookupHandleMock = vi.fn<
  (handle: string) => Promise<{
    kind: "verified" | "publicOnly";
    handle: string;
    actorUrl: string;
    shareUri?: string | null;
    verifyFailure?: string | null;
  }>
>();

vi.mock("./api", () => ({
  importCard: (uri: string) => importCardMock(uri),
  pairAccept: (uri: string) => pairAcceptMock(uri),
  importPairUri: (uri: string) => importPairUriMock(uri),
}));

vi.mock("../fediverse/api", () => ({
  lookupHandle: (handle: string) => lookupHandleMock(handle),
}));

const openQrScanModalMock = vi.fn<() => Promise<string | null>>();

vi.mock("./qrScanModal", () => ({
  openQrScanModal: () => openQrScanModalMock(),
}));

const VALID = "x0x://agent/abcdefghijklmnop";
const VALID_V3
  = "fetchit://share/v3/"
    + "aa".repeat(32)
    + "/"
    + "bb".repeat(32)
    + "?relay=https://relay.example/";
const VALID_POINTER
  = "x0x://pair/" + "ab".repeat(32) + "?r=https%3A%2F%2Frelay.example";

let host: HTMLElement;

beforeEach(() => {
  importCardMock.mockReset();
  pairAcceptMock.mockReset();
  importPairUriMock.mockReset();
  lookupHandleMock.mockReset();
  openQrScanModalMock.mockReset();
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
  it("only enables Add for a v2 x0x://agent/ or v3 fetchit://share/v3/ prefix", () => {
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

    input.value = VALID_V3;
    input.dispatchEvent(new Event("input"));
    expect(btn.disabled).toBe(false);
  });

  it("dispatches v3 URIs to pairAccept and surfaces the returned agentIdHex", async () => {
    pairAcceptMock.mockResolvedValueOnce({ agentIdHex: "deadbeef" });
    const onImported = vi.fn();
    mountAddContact(host, { onClose: () => {}, onImported });
    const input = getInput();
    const btn = getAddBtn();

    input.value = `  ${VALID_V3}\n`;
    input.dispatchEvent(new Event("input"));
    btn.click();
    await Promise.resolve();
    await Promise.resolve();

    expect(pairAcceptMock).toHaveBeenCalledWith(VALID_V3);
    expect(importCardMock).not.toHaveBeenCalled();
    expect(onImported).toHaveBeenCalledWith({ agentIdHex: "deadbeef" });
    expect(getStatus().textContent).toBe("Imported.");
  });

  it("shows 'Fetching profile…' (not 'Importing…') while a v3 accept is in flight", async () => {
    let resolveAccept: ((v: { agentIdHex: string }) => void) | undefined;
    pairAcceptMock.mockImplementationOnce(
      () =>
        new Promise<{ agentIdHex: string }>((resolve) => {
          resolveAccept = resolve;
        }),
    );
    mountAddContact(host, { onClose: () => {}, onImported: () => {} });
    const input = getInput();
    const btn = getAddBtn();

    input.value = VALID_V3;
    input.dispatchEvent(new Event("input"));
    btn.click();
    await Promise.resolve();

    expect(getStatus().textContent).toBe("Fetching profile…");
    resolveAccept?.({ agentIdHex: "ff" });
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

  it("uses a multi-row textarea with a plain-language aria-label", () => {
    mountAddContact(host, { onClose: () => {}, onImported: () => {} });
    const input = getInput();
    expect(input.tagName).toBe("TEXTAREA");
    expect(input.rows).toBeGreaterThanOrEqual(2);
    expect(input.getAttribute("aria-label")).toBe("Share link");
  });

  it("enables Add for an x0x://pair/ pointer URI", () => {
    mountAddContact(host, { onClose: () => {}, onImported: () => {} });
    const btn = getAddBtn();
    const input = getInput();

    input.value = VALID_POINTER;
    input.dispatchEvent(new Event("input"));
    expect(btn.disabled).toBe(false);
  });

  it("routes a pointer URI to importPairUri (not importCard / pairAccept)", async () => {
    importPairUriMock.mockResolvedValueOnce(undefined);
    const onImported = vi.fn();
    mountAddContact(host, { onClose: () => {}, onImported });
    const input = getInput();
    const btn = getAddBtn();

    input.value = `  ${VALID_POINTER}\n`;
    input.dispatchEvent(new Event("input"));
    btn.click();
    await Promise.resolve();
    await Promise.resolve();

    expect(importPairUriMock).toHaveBeenCalledWith(VALID_POINTER);
    expect(importCardMock).not.toHaveBeenCalled();
    expect(pairAcceptMock).not.toHaveBeenCalled();
    expect(onImported).toHaveBeenCalledTimes(1);
    expect(getStatus().textContent).toBe("Imported.");
  });

  it("detectUriKind edges: case-sensitive prefix, edge-trim only", () => {
    mountAddContact(host, { onClose: () => {}, onImported: () => {} });
    const input = getInput();
    const btn = getAddBtn();

    // Uppercase scheme/host does NOT match: the prefix check is
    // case-sensitive by intent (the daemon emits lowercase URIs).
    input.value = "X0X://PAIR/" + "ab".repeat(32) + "?r=https://relay.example";
    input.dispatchEvent(new Event("input"));
    expect(btn.disabled).toBe(true);

    // A pointer URI followed by embedded newlines + garbage still enables
    // Add: trim() only strips the edges, so the leading prefix is intact.
    input.value = VALID_POINTER + "\n\ngarbage";
    input.dispatchEvent(new Event("input"));
    expect(btn.disabled).toBe(false);
  });

  it("surfaces the honest error when an edge-trimmed pointer URI keeps an embedded newline", async () => {
    // trim() leaves the embedded "\n\ngarbage" in place, so the daemon's
    // importPairUri rejects the malformed URI; the dialog shows the honest
    // re-share copy and re-enables Add.
    const dirty = VALID_POINTER + "\n\ngarbage";
    importPairUriMock.mockRejectedValueOnce(new Error("invalid pair URI"));
    const onImported = vi.fn();
    mountAddContact(host, { onClose: () => {}, onImported });
    const input = getInput();
    const btn = getAddBtn();

    input.value = dirty;
    input.dispatchEvent(new Event("input"));
    btn.click();
    await Promise.resolve();
    await Promise.resolve();

    // The trimmed (still-dirty) value is forwarded verbatim.
    expect(importPairUriMock).toHaveBeenCalledWith(dirty.trim());
    const status = getStatus().textContent ?? "";
    expect(status).toMatch(/re-share/i);
    expect(btn.disabled).toBe(false);
    expect(onImported).not.toHaveBeenCalled();
  });

  it("routing exclusivity: pointer hits only importPairUri", async () => {
    importPairUriMock.mockResolvedValueOnce(undefined);
    mountAddContact(host, { onClose: () => {}, onImported: () => {} });
    const input = getInput();
    const btn = getAddBtn();

    input.value = VALID_POINTER;
    input.dispatchEvent(new Event("input"));
    btn.click();
    await Promise.resolve();
    await Promise.resolve();

    expect(importPairUriMock).toHaveBeenCalledTimes(1);
    expect(importCardMock).not.toHaveBeenCalled();
    expect(pairAcceptMock).not.toHaveBeenCalled();
  });

  it("routing exclusivity: v2 card hits only importCard", async () => {
    importCardMock.mockResolvedValueOnce(undefined);
    mountAddContact(host, { onClose: () => {}, onImported: () => {} });
    const input = getInput();
    const btn = getAddBtn();

    input.value = VALID;
    input.dispatchEvent(new Event("input"));
    btn.click();
    await Promise.resolve();
    await Promise.resolve();

    expect(importCardMock).toHaveBeenCalledTimes(1);
    expect(importPairUriMock).not.toHaveBeenCalled();
    expect(pairAcceptMock).not.toHaveBeenCalled();
  });

  it("routing exclusivity: v3 share hits only pairAccept", async () => {
    pairAcceptMock.mockResolvedValueOnce({ agentIdHex: "deadbeef" });
    mountAddContact(host, { onClose: () => {}, onImported: () => {} });
    const input = getInput();
    const btn = getAddBtn();

    input.value = VALID_V3;
    input.dispatchEvent(new Event("input"));
    btn.click();
    await Promise.resolve();
    await Promise.resolve();

    expect(pairAcceptMock).toHaveBeenCalledTimes(1);
    expect(importCardMock).not.toHaveBeenCalled();
    expect(importPairUriMock).not.toHaveBeenCalled();
  });

  it("renders an honest 'ask them to re-share' error when the relay is unreachable", async () => {
    importPairUriMock.mockRejectedValueOnce(
      new Error("could not reach any of their relays: timed out"),
    );
    const onImported = vi.fn();
    mountAddContact(host, { onClose: () => {}, onImported });
    const input = getInput();
    const btn = getAddBtn();

    input.value = VALID_POINTER;
    input.dispatchEvent(new Event("input"));
    btn.click();
    await Promise.resolve();
    await Promise.resolve();

    const status = getStatus().textContent ?? "";
    expect(status).toMatch(/re-share/i);
    expect(btn.disabled).toBe(false);
    expect(onImported).not.toHaveBeenCalled();
  });
});

describe("mountAddContact — QR scan", () => {
  function getScanBtn(): HTMLButtonElement {
    return host.querySelector<HTMLButtonElement>(".chat-dialog__scan")!;
  }

  it("renders a Scan a QR code button that is not a dialog action", () => {
    mountAddContact(host, { onClose: () => {}, onImported: () => {} });
    const scanBtn = getScanBtn();
    expect(scanBtn).not.toBeNull();
    expect(scanBtn.textContent).toBe("Scan a QR code");
    // Existing selectors index .chat-dialog__btn for Add/Cancel; the
    // scan affordance must not shift them.
    expect(scanBtn.classList.contains("chat-dialog__btn")).toBe(false);
    expect(getAddBtn().textContent).toBe("Add");
  });

  it("populates the textarea from a decoded QR and runs validation", async () => {
    openQrScanModalMock.mockResolvedValueOnce(VALID_V3);
    mountAddContact(host, { onClose: () => {}, onImported: () => {} });

    getScanBtn().click();
    await vi.waitFor(() => {
      expect(getInput().value).toBe(VALID_V3);
    });
    expect(getAddBtn().disabled).toBe(false);
  });

  it("leaves Add disabled when the QR is not a share link", async () => {
    openQrScanModalMock.mockResolvedValueOnce("https://example.com/");
    mountAddContact(host, { onClose: () => {}, onImported: () => {} });

    getScanBtn().click();
    await vi.waitFor(() => {
      expect(getInput().value).toBe("https://example.com/");
    });
    expect(getAddBtn().disabled).toBe(true);
  });

  it("changes nothing on cancel", async () => {
    openQrScanModalMock.mockResolvedValueOnce(null);
    mountAddContact(host, { onClose: () => {}, onImported: () => {} });

    getScanBtn().click();
    await vi.waitFor(() => {
      expect(getScanBtn().disabled).toBe(false);
    });
    expect(getInput().value).toBe("");
    expect(getAddBtn().disabled).toBe(true);
    expect(getStatus().textContent).toBe("");
  });

  it("shows the no-camera copy inline when the scanner has no device", async () => {
    const { QrScanError } = await import("./qrScan");
    openQrScanModalMock.mockRejectedValueOnce(new QrScanError("no-camera", "x"));
    mountAddContact(host, { onClose: () => {}, onImported: () => {} });

    getScanBtn().click();
    await vi.waitFor(() => {
      expect(getStatus().textContent).toBe(
        "No camera found on this computer. Paste the invite link instead.",
      );
    });
    expect(getScanBtn().disabled).toBe(false);
  });

  it("shows the blocked-permission copy when access is denied", async () => {
    const { QrScanError } = await import("./qrScan");
    openQrScanModalMock.mockRejectedValueOnce(new QrScanError("denied", "x"));
    mountAddContact(host, { onClose: () => {}, onImported: () => {} });

    getScanBtn().click();
    await vi.waitFor(() => {
      expect(getStatus().textContent).toBe(
        "Camera access was blocked. You can paste the invite link instead.",
      );
    });
  });

  it("locks the scan button while the modal is open", async () => {
    let resolveScan: ((v: string | null) => void) | undefined;
    openQrScanModalMock.mockImplementationOnce(
      () =>
        new Promise<string | null>((resolve) => {
          resolveScan = resolve;
        }),
    );
    mountAddContact(host, { onClose: () => {}, onImported: () => {} });

    getScanBtn().click();
    await Promise.resolve();
    expect(getScanBtn().disabled).toBe(true);

    resolveScan?.(null);
    await vi.waitFor(() => {
      expect(getScanBtn().disabled).toBe(false);
    });
  });
});

describe("mountAddContact — fediverse handles", () => {
  const HANDLE = "@josh@etchit.io";
  const SHARE = `fetchit://share/v3/${"aa".repeat(32)}/${"bb".repeat(32)}?relay=x`;

  it("enables Add for a well-formed handle", () => {
    mountAddContact(host, { onClose: () => {}, onImported: () => {} });
    const input = getInput();
    const btn = getAddBtn();
    input.value = HANDLE;
    input.dispatchEvent(new Event("input"));
    expect(btn.disabled).toBe(false);
  });

  it("imports a verified handle via lookup then pair-accept", async () => {
    lookupHandleMock.mockResolvedValueOnce({
      kind: "verified",
      handle: HANDLE,
      actorUrl: "https://etchit.io/actors/josh",
      shareUri: SHARE,
      verifyFailure: null,
    });
    pairAcceptMock.mockResolvedValueOnce({ agentIdHex: "aa".repeat(32) });
    const onImported = vi.fn();
    mountAddContact(host, { onClose: () => {}, onImported });
    const input = getInput();
    input.value = HANDLE;
    input.dispatchEvent(new Event("input"));
    getAddBtn().click();
    await vi.waitFor(() => {
      expect(onImported).toHaveBeenCalledWith({ agentIdHex: "aa".repeat(32) });
    });
    expect(lookupHandleMock).toHaveBeenCalledWith(HANDLE);
    expect(pairAcceptMock).toHaveBeenCalledWith(SHARE);
    expect(getStatus().textContent).toBe("Imported.");
  });

  it("rejects a public-only handle with honest copy", async () => {
    lookupHandleMock.mockResolvedValueOnce({
      kind: "publicOnly",
      handle: "@g@m.social",
      actorUrl: "https://m.social/users/g",
      verifyFailure: null,
    });
    const onImported = vi.fn();
    mountAddContact(host, { onClose: () => {}, onImported });
    const input = getInput();
    input.value = "@g@m.social";
    input.dispatchEvent(new Event("input"));
    const btn = getAddBtn();
    btn.click();
    await vi.waitFor(() => {
      expect(getStatus().textContent).toMatch(/isn't linked to a fetch>it identity/);
    });
    expect(btn.disabled).toBe(false);
    expect(onImported).not.toHaveBeenCalled();
    expect(pairAcceptMock).not.toHaveBeenCalled();
  });

  it("surfaces a failed attestation distinctly", async () => {
    lookupHandleMock.mockResolvedValueOnce({
      kind: "publicOnly",
      handle: "@evil@etchit.io",
      actorUrl: "https://etchit.io/actors/evil",
      verifyFailure: "signature does not verify",
    });
    mountAddContact(host, { onClose: () => {}, onImported: () => {} });
    const input = getInput();
    input.value = "@evil@etchit.io";
    input.dispatchEvent(new Event("input"));
    getAddBtn().click();
    await vi.waitFor(() => {
      expect(getStatus().textContent).toMatch(/Couldn't verify that handle/);
    });
  });
});
