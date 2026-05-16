// Share-address modal. Renders the active tab's address as a QR code, plus
// copyable text in both bare-hex and `autonomi://`-prefixed forms.
//
// Stays out of the toolbar's way: invoked by Ctrl/Cmd+Shift+S, or by clicking
// the ▦ button in the header. Closes on Esc, on backdrop click, or on the
// explicit close affordance.

import { renderQrSvg } from "../qr";

export interface QrModalApi {
  open(address: string): void;
  close(): void;
  isOpen(): boolean;
}

export function mountQrModal(host: HTMLElement): QrModalApi {
  host.classList.add("qr-modal-host");
  host.hidden = true;
  host.setAttribute("role", "dialog");
  host.setAttribute("aria-modal", "true");
  host.setAttribute("aria-label", "Share address");

  host.innerHTML = `
    <div class="qr-modal-backdrop" data-close="1"></div>
    <div class="qr-modal-card" role="document">
      <header class="qr-modal-header">
        <h2 class="qr-modal-brand">fetch<span class="qr-modal-brand-chev">&gt;</span>it</h2>
        <button type="button" class="qr-modal-close" aria-label="Close (Esc)">×</button>
      </header>
      <div class="qr-modal-qr" aria-live="polite"></div>
      <p class="qr-modal-addr"><code></code></p>
      <div class="qr-modal-actions">
        <button type="button" class="qr-modal-copy-hex">Copy address</button>
        <button type="button" class="qr-modal-copy-url">Copy autonomi://…</button>
      </div>
      <p class="qr-modal-footer">
        scan with fetch<span class="brand-mark">&gt;</span>it on Android &middot; <span class="qr-modal-domain">etchit.io</span>
      </p>
    </div>
  `;

  const qrSlot = host.querySelector(".qr-modal-qr") as HTMLDivElement;
  const codeEl = host.querySelector(".qr-modal-addr code") as HTMLElement;
  const copyHex = host.querySelector(".qr-modal-copy-hex") as HTMLButtonElement;
  const copyUrl = host.querySelector(".qr-modal-copy-url") as HTMLButtonElement;
  const closeBtn = host.querySelector(".qr-modal-close") as HTMLButtonElement;

  let currentAddr: string | null = null;

  const flash = (btn: HTMLButtonElement, msg: string): void => {
    const original = btn.textContent ?? "";
    btn.textContent = msg;
    btn.disabled = true;
    window.setTimeout(() => {
      btn.textContent = original;
      btn.disabled = false;
    }, 1100);
  };

  const onKey = (e: KeyboardEvent): void => {
    if (e.key === "Escape" && !host.hidden) {
      e.preventDefault();
      api.close();
    }
  };

  const onBackdrop = (e: MouseEvent): void => {
    const t = e.target as HTMLElement | null;
    if (t?.dataset.close === "1") api.close();
  };

  const api: QrModalApi = {
    open(address) {
      currentAddr = address;
      codeEl.textContent = address;
      // Copper-colored center mark so the QR carries the brand chevron even
      // when the modal frame is cropped out of a screenshot.
      qrSlot.replaceChildren(
        renderQrSvg(`autonomi://${address}`, {
          cellSize: 8,
          errorCorrectionLevel: "H",
          centerLogo: { text: ">", sizeRatio: 0.16, color: "var(--copper)" },
        }),
      );
      host.hidden = false;
      document.addEventListener("keydown", onKey);
      host.addEventListener("click", onBackdrop);
      closeBtn.focus();
    },
    close() {
      host.hidden = true;
      currentAddr = null;
      document.removeEventListener("keydown", onKey);
      host.removeEventListener("click", onBackdrop);
    },
    isOpen: () => !host.hidden,
  };

  copyHex.addEventListener("click", () => {
    if (!currentAddr) return;
    void navigator.clipboard.writeText(currentAddr).then(
      () => flash(copyHex, "Copied!"),
      () => flash(copyHex, "Copy failed"),
    );
  });

  copyUrl.addEventListener("click", () => {
    if (!currentAddr) return;
    void navigator.clipboard.writeText(`autonomi://${currentAddr}`).then(
      () => flash(copyUrl, "Copied!"),
      () => flash(copyUrl, "Copy failed"),
    );
  });

  closeBtn.addEventListener("click", () => api.close());

  return api;
}
