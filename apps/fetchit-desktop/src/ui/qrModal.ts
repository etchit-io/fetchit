// Share-address modal. Renders the active tab's address as a QR code, plus
// copyable text in both bare-hex and `autonomi://`-prefixed forms.
//
// Stays out of the toolbar's way: invoked by Ctrl/Cmd+Shift+S, or by clicking
// the ▦ button in the header. Closes on Esc, on backdrop click, or on the
// explicit close affordance.

import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";

import { abbreviateAddress, renderExportCardSvg, renderQrSvg } from "../qr";

export interface QrModalApi {
  /** `title` is shown verbatim above the address row when supplied. Callers
   *  pass the etch / page / file title so the recipient sees what they're
   *  about to open before they scan. */
  open(address: string, title?: string | null): void;
  /** Render a non-address payload (e.g. a `fetchit://import?…` URL
   *  carrying a bookmark list). `summary` is shown below the QR in
   *  place of the abbreviated address. The copy + save-image actions
   *  are hidden — the QR itself is the share artifact. */
  openImport(url: string, summary: string): void;
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
      <input
        type="text"
        class="qr-modal-title-input"
        maxlength="60"
        placeholder="add a title (optional)"
        aria-label="Share title"
        autocomplete="off"
        spellcheck="false"
      />
      <p class="qr-modal-addr"><code></code></p>
      <div class="qr-modal-actions">
        <button type="button" class="qr-modal-copy-hex">address</button>
        <button type="button" class="qr-modal-copy-url">autonomi://&hellip;</button>
        <button type="button" class="qr-modal-save-png">save image</button>
        <button type="button" class="qr-modal-copy-png">copy image</button>
      </div>
      <p class="qr-modal-footer">
        scan with fetch<span class="brand-mark">&gt;</span>it on mobile &middot; <span class="qr-modal-domain">etchit.io</span>
      </p>
    </div>
  `;

  const qrSlot = host.querySelector(".qr-modal-qr") as HTMLDivElement;
  const titleInput = host.querySelector(".qr-modal-title-input") as HTMLInputElement;
  const codeEl = host.querySelector(".qr-modal-addr code") as HTMLElement;
  const copyHex = host.querySelector(".qr-modal-copy-hex") as HTMLButtonElement;
  const copyUrl = host.querySelector(".qr-modal-copy-url") as HTMLButtonElement;
  const savePng = host.querySelector(".qr-modal-save-png") as HTMLButtonElement;
  const copyPng = host.querySelector(".qr-modal-copy-png") as HTMLButtonElement;
  const closeBtn = host.querySelector(".qr-modal-close") as HTMLButtonElement;

  // Rasterise the export-card SVG (wordmark + QR + address + footer)
  // to a PNG blob. Shared path for Save image and Copy image.
  async function rasterise(): Promise<Blob | null> {
    if (!currentAddr) return null;
    // Read the live input each call so a title typed after the modal
    // opened lands on the exported card.
    const card = renderExportCardSvg(currentAddr, titleInput.value);
    const xml = new XMLSerializer().serializeToString(card);
    const svgUrl = URL.createObjectURL(new Blob([xml], { type: "image/svg+xml" }));
    try {
      const img = new Image();
      await new Promise<void>((resolve, reject) => {
        img.onload = () => resolve();
        img.onerror = () => reject(new Error("svg load failed"));
        img.src = svgUrl;
      });
      const w = Number(card.getAttribute("width")) || 720;
      const h = Number(card.getAttribute("height")) || 900;
      const canvas = document.createElement("canvas");
      canvas.width = w;
      canvas.height = h;
      const ctx = canvas.getContext("2d");
      if (!ctx) return null;
      ctx.fillStyle = "#f5f2eb";
      ctx.fillRect(0, 0, w, h);
      ctx.drawImage(img, 0, 0, w, h);
      return await new Promise<Blob | null>((resolve) => {
        canvas.toBlob((b) => resolve(b), "image/png");
      });
    } finally {
      URL.revokeObjectURL(svgUrl);
    }
  }

  let currentAddr: string | null = null;

  const actionsRow = host.querySelector(".qr-modal-actions") as HTMLElement;

  const setImportModeVisibility = (importMode: boolean): void => {
    actionsRow.style.display = importMode ? "none" : "";
    titleInput.style.display = importMode ? "none" : "";
  };

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
    open(address, title) {
      currentAddr = address;
      // Pre-fill the title with any caller-derived label (etch title,
      // page <title>, filename). The input stays editable so the
      // caller's label can be overridden before export.
      titleInput.value = (title ?? "").trim();
      codeEl.textContent = abbreviateAddress(address);
      // Copper-colored center mark — survives screenshots cropped to
      // just the QR.
      qrSlot.replaceChildren(
        renderQrSvg(`autonomi://${address}`, {
          cellSize: 8,
          errorCorrectionLevel: "H",
          centerLogo: { text: ">", sizeRatio: 0.16, color: "var(--copper)" },
        }),
      );
      setImportModeVisibility(false);
      host.hidden = false;
      document.addEventListener("keydown", onKey);
      host.addEventListener("click", onBackdrop);
      closeBtn.focus();
    },
    openImport(url, summary) {
      currentAddr = null;
      titleInput.value = "";
      codeEl.textContent = summary;
      // Smaller cells + medium ECC let the QR fit the larger
      // import-URL payload (~1–2 KB) while staying readable; the
      // single-address QR uses larger cells + H-level ECC because the
      // payload is fixed-size and small.
      qrSlot.replaceChildren(
        renderQrSvg(url, {
          cellSize: 6,
          errorCorrectionLevel: "M",
          centerLogo: { text: ">", sizeRatio: 0.16, color: "var(--copper)" },
        }),
      );
      setImportModeVisibility(true);
      host.hidden = false;
      document.addEventListener("keydown", onKey);
      host.addEventListener("click", onBackdrop);
      closeBtn.focus();
    },
    close() {
      host.hidden = true;
      currentAddr = null;
      titleInput.value = "";
      setImportModeVisibility(false);
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
      try {
        const suggested = `fetchit-${currentAddr.slice(0, 8)}.png`;
        const path = await save({
          defaultPath: suggested,
          filters: [{ name: "PNG image", extensions: ["png"] }],
        });
        if (!path) return;
        const bytes = new Uint8Array(await blob.arrayBuffer());
        await invoke("save_bytes_to_path", { path, data: Array.from(bytes) });
        flash(savePng, "Saved!");
      } catch {
        flash(savePng, "Save failed");
      }
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
        // Go through one backend command, not the two-hop JS chain
        // (`Image.fromBytes` + `writeImage`). The two-hop form crosses
        // the IPC boundary twice with an `Image` resource handle in
        // between, which webkit2gtk drops on the floor sometimes. The
        // backend command does the decode + clipboard write in one
        // Rust frame, no intermediate resource handle to lose.
        const bytes = new Uint8Array(await blob.arrayBuffer());
        await invoke("copy_png_to_clipboard", { data: Array.from(bytes) });
        flash(copyPng, "Copied!");
      } catch {
        flash(copyPng, "Copy failed");
      }
    })();
  });

  closeBtn.addEventListener("click", () => api.close());

  return api;
}
