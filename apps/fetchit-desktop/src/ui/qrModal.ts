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
        <button type="button" class="qr-modal-save-png">Save image</button>
        <button type="button" class="qr-modal-copy-png">Copy image</button>
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
  const savePng = host.querySelector(".qr-modal-save-png") as HTMLButtonElement;
  const copyPng = host.querySelector(".qr-modal-copy-png") as HTMLButtonElement;
  const closeBtn = host.querySelector(".qr-modal-close") as HTMLButtonElement;

  // Rasterise the currently-shown QR SVG to a 1024×1024 PNG blob with a white
  // background. White is critical for scannability — most cameras need high
  // contrast against the QR modules, and our modal renders on bone surface.
  async function rasterise(): Promise<Blob | null> {
    const svg = qrSlot.querySelector("svg");
    if (!svg) return null;
    const xml = new XMLSerializer().serializeToString(svg);
    const svgUrl = URL.createObjectURL(new Blob([xml], { type: "image/svg+xml" }));
    try {
      const img = new Image();
      await new Promise<void>((resolve, reject) => {
        img.onload = () => resolve();
        img.onerror = () => reject(new Error("svg load failed"));
        img.src = svgUrl;
      });
      const canvas = document.createElement("canvas");
      const size = 1024;
      canvas.width = size;
      canvas.height = size;
      const ctx = canvas.getContext("2d");
      if (!ctx) return null;
      ctx.fillStyle = "#ffffff";
      ctx.fillRect(0, 0, size, size);
      ctx.drawImage(img, 0, 0, size, size);
      return await new Promise<Blob | null>((resolve) => {
        canvas.toBlob((b) => resolve(b), "image/png");
      });
    } finally {
      URL.revokeObjectURL(svgUrl);
    }
  }

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

  savePng.addEventListener("click", () => {
    if (!currentAddr) return;
    void (async () => {
      const blob = await rasterise();
      if (!blob) {
        flash(savePng, "Save failed");
        return;
      }
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `fetchit-${currentAddr.slice(0, 8)}.png`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      flash(savePng, "Saved!");
    })();
  });

  copyPng.addEventListener("click", () => {
    if (!currentAddr) return;
    void (async () => {
      const blob = await rasterise();
      if (!blob) {
        flash(copyPng, "Copy failed");
        return;
      }
      try {
        // ClipboardItem with image/png works in modern browsers + Tauri WebView.
        // If the surrounding browser blocks it (e.g., not focused), fall back
        // to copying a markdown image link to the rendered PNG isn't useful;
        // we just surface the failure.
        await navigator.clipboard.write([
          new ClipboardItem({ "image/png": blob }),
        ]);
        flash(copyPng, "Copied!");
      } catch {
        flash(copyPng, "Copy failed");
      }
    })();
  });

  closeBtn.addEventListener("click", () => api.close());

  return api;
}
