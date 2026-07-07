import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { QrScanError, type ScanQrOptions } from "./qrScan";
import { openQrScanModal } from "./qrScanModal";

const DECODED = "fetchit://share/v3/" + "aa".repeat(32) + "/" + "bb".repeat(32);

/// A controllable stand-in for scanQrFromCamera: records its options
/// and lets the test settle the scan whenever it wants.
function fakeScan(): {
  scan: (opts: ScanQrOptions) => Promise<string | null>;
  opts: () => ScanQrOptions;
  resolve: (v: string | null) => void;
  reject: (e: unknown) => void;
} {
  let seen: ScanQrOptions | undefined;
  let resolveFn: ((v: string | null) => void) | undefined;
  let rejectFn: ((e: unknown) => void) | undefined;
  return {
    scan: (opts) => {
      seen = opts;
      return new Promise<string | null>((resolve, reject) => {
        resolveFn = resolve;
        rejectFn = reject;
      });
    },
    opts: () => {
      if (!seen) throw new Error("scan not called");
      return seen;
    },
    resolve: (v) => resolveFn?.(v),
    reject: (e) => rejectFn?.(e),
  };
}

function overlay(): HTMLElement | null {
  return document.querySelector(".chat-dialog--scan");
}

let opener: HTMLButtonElement;

beforeEach(() => {
  opener = document.createElement("button");
  document.body.appendChild(opener);
  opener.focus();
});

afterEach(() => {
  document.querySelectorAll(".chat-dialog--scan").forEach((el) => el.remove());
  opener.remove();
});

describe("openQrScanModal", () => {
  it("mounts a viewfinder, guidance line, and Cancel, then scans", async () => {
    const s = fakeScan();
    const done = openQrScanModal({ scan: s.scan });

    const host = overlay()!;
    expect(host).not.toBeNull();
    expect(host.getAttribute("role")).toBe("dialog");
    expect(host.getAttribute("aria-modal")).toBe("true");
    const video = host.querySelector("video.chat-scan__video");
    expect(video).not.toBeNull();
    expect(host.textContent).toContain("Point the camera at the QR code");
    expect(host.textContent).toContain("Cancel");
    // The scanner gets the mounted viewfinder and a live signal.
    expect(s.opts().video).toBe(video);
    expect(s.opts().signal.aborted).toBe(false);

    s.resolve(null);
    await done;
  });

  it("resolves the decoded text and removes the modal", async () => {
    const s = fakeScan();
    const done = openQrScanModal({ scan: s.scan });
    s.resolve(DECODED);
    await expect(done).resolves.toBe(DECODED);
    expect(overlay()).toBeNull();
  });

  it("focuses Cancel while open and restores the opener on close", async () => {
    const s = fakeScan();
    const done = openQrScanModal({ scan: s.scan });
    const cancel = overlay()!.querySelector("button")!;
    expect(document.activeElement).toBe(cancel);

    s.resolve(null);
    await done;
    expect(document.activeElement).toBe(opener);
  });

  it("Cancel aborts the scan signal", async () => {
    const s = fakeScan();
    const done = openQrScanModal({ scan: s.scan });
    overlay()!.querySelector("button")!.click();
    expect(s.opts().signal.aborted).toBe(true);

    // The real scanner resolves null once its signal aborts.
    s.resolve(null);
    await expect(done).resolves.toBeNull();
    expect(overlay()).toBeNull();
  });

  it("Escape aborts the scan signal", async () => {
    const s = fakeScan();
    const done = openQrScanModal({ scan: s.scan });
    document.dispatchEvent(
      new KeyboardEvent("keydown", { key: "Escape", bubbles: true }),
    );
    expect(s.opts().signal.aborted).toBe(true);
    s.resolve(null);
    await done;
  });

  it("backdrop click aborts, panel click does not", async () => {
    const s = fakeScan();
    const done = openQrScanModal({ scan: s.scan });
    const host = overlay()!;
    const panel = host.querySelector<HTMLElement>(".chat-scan__panel")!;

    panel.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(s.opts().signal.aborted).toBe(false);

    host.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(s.opts().signal.aborted).toBe(true);
    s.resolve(null);
    await done;
  });

  it("traps Tab on the Cancel control", async () => {
    const s = fakeScan();
    const done = openQrScanModal({ scan: s.scan });
    const cancel = overlay()!.querySelector("button")!;
    opener.focus();
    document.dispatchEvent(
      new KeyboardEvent("keydown", { key: "Tab", bubbles: true }),
    );
    expect(document.activeElement).toBe(cancel);
    s.resolve(null);
    await done;
  });

  it("removes the modal and re-raises typed scan errors", async () => {
    const s = fakeScan();
    const done = openQrScanModal({ scan: s.scan });
    s.reject(new QrScanError("no-camera", "none"));
    await expect(done).rejects.toMatchObject({ kind: "no-camera" });
    expect(overlay()).toBeNull();
    expect(document.activeElement).toBe(opener);
  });

  it("stops listening for keys after close", async () => {
    const s = fakeScan();
    const done = openQrScanModal({ scan: s.scan });
    s.resolve(null);
    await done;

    // A stray Escape after close must not touch the (settled) signal
    // or throw; the document-level listener is gone.
    expect(() =>
      document.dispatchEvent(
        new KeyboardEvent("keydown", { key: "Escape", bubbles: true }),
      ),
    ).not.toThrow();
  });
});
