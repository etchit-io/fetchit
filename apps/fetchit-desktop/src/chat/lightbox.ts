// Full-view image lightbox for inline-image bubbles (spec 2.4). Clicking
// a bubble thumbnail opens the image at full size in a centered overlay.
//
// Reuses the single reader image renderer (`src/renderers/image.ts`) for
// the actual <img> so there is one image-display path. Follows the same
// webkit2gtk-safe singleton-host discipline as confirmDialog.ts: the
// overlay structure (positioning class + children) is built exactly once
// while hidden; per-open only `hidden` toggles and the nested image
// container's content swaps, never the host class or structure.

import type { Attachment } from "./types";
import { renderImage } from "../renderers/image";
import { attachmentDataUrl, b64ToBytes } from "./imageAttach";

interface LightboxHost {
  host: HTMLDivElement;
  imageBox: HTMLDivElement;
}

let ref: LightboxHost | null = null;
let escHandler: ((e: KeyboardEvent) => void) | null = null;

function closeLightbox(): void {
  if (!ref) return;
  ref.host.hidden = true;
  ref.imageBox.replaceChildren();
  if (escHandler) {
    document.removeEventListener("keydown", escHandler, true);
    escHandler = null;
  }
}

function ensureHost(): LightboxHost {
  if (ref) return ref;

  const host = document.createElement("div");
  host.className = "chat-lightbox";
  host.hidden = true;

  const panel = document.createElement("div");
  panel.className = "chat-lightbox__panel";

  const close = document.createElement("button");
  close.type = "button";
  close.className = "chat-lightbox__close";
  close.title = "Close";
  close.setAttribute("aria-label", "Close");
  close.textContent = "×";

  const imageBox = document.createElement("div");
  imageBox.className = "chat-lightbox__image";

  panel.append(close, imageBox);
  host.appendChild(panel);
  document.body.appendChild(host);

  // Backdrop click closes; clicks inside the panel do not bubble to a
  // close. Close button + Escape (wired per-open) also dismiss.
  host.addEventListener("click", (e) => {
    if (e.target === host) closeLightbox();
  });
  close.addEventListener("click", closeLightbox);

  ref = { host, imageBox };
  return ref;
}

/// Open the given attachment full-size in the overlay. Idempotent on the
/// host — repeated opens reuse the one overlay and just swap the image.
export function openImageLightbox(att: Attachment): void {
  const { host, imageBox } = ensureHost();
  imageBox.replaceChildren();
  // byteLen feeds only the renderer's error-fallback caption.
  const byteLen = b64ToBytes(att.bytes_b64).length;
  renderImage(
    { kind: "image", mime: att.mime, byteLen },
    imageBox,
    attachmentDataUrl(att),
  );
  host.hidden = false;
  if (!escHandler) {
    escHandler = (e: KeyboardEvent) => {
      if (e.key === "Escape") closeLightbox();
    };
    document.addEventListener("keydown", escHandler, true);
  }
}
