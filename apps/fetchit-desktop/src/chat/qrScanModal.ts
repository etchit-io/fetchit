// Camera viewfinder modal for the add-contact QR scan. Follows the
// chat-dialog overlay pattern: fixed backdrop, Esc / Cancel / backdrop
// click all close it, focus is trapped on the single Cancel control
// and restored to the opener on exit.
//
// Resolves the decoded QR text, `null` on cancel, and rejects with the
// scanner's typed `QrScanError` so the opener can show specific copy.

import { scanQrFromCamera } from "./qrScan";

export interface QrScanModalOptions {
  /** Scanner implementation; defaults to `scanQrFromCamera`. Test seam. */
  scan?: typeof scanQrFromCamera;
}

/// Mount the scan modal on `document.body` and run one scan session.
export async function openQrScanModal(
  opts: QrScanModalOptions = {},
): Promise<string | null> {
  const scan = opts.scan ?? scanQrFromCamera;
  const opener
    = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;

  const overlay = document.createElement("div");
  overlay.className = "chat-dialog chat-dialog--scan";
  overlay.setAttribute("role", "dialog");
  overlay.setAttribute("aria-modal", "true");
  overlay.setAttribute("aria-label", "Scan a QR code");

  const panel = document.createElement("div");
  panel.className = "chat-dialog__panel chat-scan__panel";

  const title = document.createElement("h3");
  title.textContent = "Scan a QR code";

  const video = document.createElement("video");
  video.className = "chat-scan__video";
  video.setAttribute("aria-label", "Camera viewfinder");

  const help = document.createElement("p");
  help.className = "chat-dialog__help";
  help.textContent = "Point the camera at the QR code";

  const actions = document.createElement("div");
  actions.className = "chat-dialog__actions";

  const cancelBtn = document.createElement("button");
  cancelBtn.type = "button";
  cancelBtn.className = "chat-dialog__btn chat-dialog__btn--ghost";
  cancelBtn.textContent = "Cancel";

  actions.appendChild(cancelBtn);
  panel.appendChild(title);
  panel.appendChild(video);
  panel.appendChild(help);
  panel.appendChild(actions);
  overlay.appendChild(panel);

  const controller = new AbortController();
  const cancel = (): void => controller.abort();

  cancelBtn.addEventListener("click", cancel);
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) cancel();
  });
  const onKey = (e: KeyboardEvent): void => {
    if (e.key === "Escape") {
      e.preventDefault();
      cancel();
    } else if (e.key === "Tab") {
      // Cancel is the only focusable control; keep focus on it.
      e.preventDefault();
      cancelBtn.focus();
    }
  };
  document.addEventListener("keydown", onKey);

  document.body.appendChild(overlay);
  cancelBtn.focus();

  try {
    return await scan({ video, signal: controller.signal });
  } finally {
    document.removeEventListener("keydown", onKey);
    overlay.remove();
    opener?.focus();
  }
}
