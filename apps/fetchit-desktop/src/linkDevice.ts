// Link-device modal. Supports both pairing roles:
//
// NEW device: generates a pairing QR + short code for an existing device to
// scan and confirm.
//
// EXISTING device: accepts a pasted fetchit://link/v1/ URI, fetches a
// preview (short code), and -- after the user confirms the codes match --
// enrolls the new device into this account.
//
// One concern per module. Mirrors the modal mechanics of src/ui/qrModal.ts.

import { invoke } from "@tauri-apps/api/core";
import { renderQrSvg } from "./qr";
import { friendlyError } from "./chat/errors";

export interface LinkDeviceModalApi {
  open(): void;
  close(): void;
  isOpen(): boolean;
}

// TTL for the generated link offer (10 minutes).
const OFFER_TTL_SECS = 600;

/** URI scheme emitted by chat_create_link_offer. */
export const LINK_OFFER_PREFIX = "fetchit://link/v1/";

/** Returns true when `value` (trimmed) is a device link-offer URI. */
export function isLinkOfferUri(value: string): boolean {
  return value.trim().startsWith(LINK_OFFER_PREFIX);
}

interface CreatedOffer {
  uri: string;
  shortCode: string;
  expMs: number;
}

interface OfferPreview {
  agentIdHex: string;
  shortCode: string;
  expired: boolean;
}

function fmtExpiry(expMs: number): string {
  const remainMs = expMs - Date.now();
  if (remainMs <= 0) return "Expired";
  const mins = Math.ceil(remainMs / 60_000);
  return `Expires in ${mins} min`;
}

export function mountLinkDeviceModal(host: HTMLElement): LinkDeviceModalApi {
  host.classList.add("qr-modal-host");
  host.hidden = true;
  host.setAttribute("role", "dialog");
  host.setAttribute("aria-modal", "true");
  host.setAttribute("aria-label", "Link a device");

  host.innerHTML = `
    <div class="qr-modal-backdrop" data-close="1"></div>
    <div class="link-device-card" role="document">
      <header class="link-device-header">
        <h2 class="link-device-heading">Link a device</h2>
        <button type="button" class="qr-modal-close" aria-label="Close (Esc)">&#xd7;</button>
      </header>

      <section class="link-device-section">
        <h3 class="link-device-section-title">Link this computer to your account</h3>
        <p class="link-device-desc">
          Generate a pairing link, then show the QR code or share the link on
          your other device. Before your other device confirms, make sure the
          pairing code matches on both screens.
        </p>
        <div class="link-device-new-idle">
          <button type="button" class="setting-action link-device-generate-btn">
            Generate pairing link
          </button>
          <p class="link-device-new-error setting-error" role="alert" hidden></p>
        </div>
        <div class="link-device-new-active" hidden>
          <div class="link-device-qr-slot"></div>
          <p class="link-device-code-label">Check this code matches on your other device:</p>
          <p class="link-device-code link-device-code--new" aria-label="Pairing code"></p>
          <p class="link-device-expiry"></p>
        </div>
      </section>

      <hr class="link-device-divider" />

      <section class="link-device-section">
        <h3 class="link-device-section-title">Add a device to your account</h3>
        <p class="link-device-desc">
          On the new device, tap "Generate pairing link" and paste that link
          below.
        </p>
        <textarea
          class="chat-dialog__uri link-device-uri-input"
          placeholder="Paste the fetchit://link/v1/... link here"
          spellcheck="false"
          rows="3"
          aria-label="Device pairing link"
        ></textarea>
        <p class="link-device-status" role="alert" aria-live="polite"></p>

        <div class="link-device-preview" hidden>
          <p class="link-device-code-label">Code shown on the new device:</p>
          <p class="link-device-code link-device-code--existing" aria-label="Pairing code from new device"></p>
          <p class="link-device-confirm-q">
            Does this match the code on your new device?
          </p>
          <div class="link-device-confirm-row">
            <button type="button" class="setting-action link-device-confirm-btn">
              Yes, link it
            </button>
            <button type="button" class="setting-action setting-action-ghost link-device-reset-btn">
              Cancel
            </button>
          </div>
        </div>

        <div class="link-device-linked" hidden>
          <p class="link-device-success">Device linked.</p>
        </div>
      </section>
    </div>
  `;

  const closeBtn = host.querySelector<HTMLButtonElement>(".qr-modal-close")!;

  // -- NEW DEVICE elements
  const generateBtn = host.querySelector<HTMLButtonElement>(".link-device-generate-btn")!;
  const newError = host.querySelector<HTMLElement>(".link-device-new-error")!;
  const newIdlePanel = host.querySelector<HTMLElement>(".link-device-new-idle")!;
  const newActivePanel = host.querySelector<HTMLElement>(".link-device-new-active")!;
  const qrSlot = host.querySelector<HTMLElement>(".link-device-qr-slot")!;
  const newCode = host.querySelector<HTMLElement>(".link-device-code--new")!;
  const expiryEl = host.querySelector<HTMLElement>(".link-device-expiry")!;

  // -- EXISTING DEVICE elements
  const uriInput = host.querySelector<HTMLTextAreaElement>(".link-device-uri-input")!;
  const statusEl = host.querySelector<HTMLElement>(".link-device-status")!;
  const previewPanel = host.querySelector<HTMLElement>(".link-device-preview")!;
  const existingCode = host.querySelector<HTMLElement>(".link-device-code--existing")!;
  const confirmBtn = host.querySelector<HTMLButtonElement>(".link-device-confirm-btn")!;
  const resetBtn = host.querySelector<HTMLButtonElement>(".link-device-reset-btn")!;
  const linkedPanel = host.querySelector<HTMLElement>(".link-device-linked")!;

  // -- NEW DEVICE side

  generateBtn.addEventListener("click", () => {
    generateBtn.disabled = true;
    generateBtn.textContent = "Working...";
    newError.hidden = true;
    void (async () => {
      try {
        const offer = await invoke<CreatedOffer>("chat_create_link_offer", {
          ttlSecs: OFFER_TTL_SECS,
        });
        qrSlot.replaceChildren(
          renderQrSvg(offer.uri, {
            cellSize: 6,
            errorCorrectionLevel: "M",
            centerLogo: { text: ">", sizeRatio: 0.14, color: "var(--copper)" },
          }),
        );
        newCode.textContent = offer.shortCode;
        expiryEl.textContent = fmtExpiry(offer.expMs);
        newIdlePanel.hidden = true;
        newActivePanel.hidden = false;
      } catch (e) {
        newError.textContent = `Couldn’t create a pairing link. ${friendlyError(e)}`;
        newError.hidden = false;
        generateBtn.textContent = "Generate pairing link";
        generateBtn.disabled = false;
      }
    })();
  });

  // -- EXISTING DEVICE side

  // Track the URI being previewed to drop stale async responses.
  let currentUri = "";

  const clearExisting = (): void => {
    previewPanel.hidden = true;
    linkedPanel.hidden = true;
    statusEl.textContent = "";
    statusEl.removeAttribute("data-error");
    confirmBtn.disabled = false;
    confirmBtn.textContent = "Yes, link it";
    currentUri = "";
  };

  uriInput.addEventListener("input", () => {
    const val = uriInput.value.trim();
    if (!isLinkOfferUri(val)) {
      previewPanel.hidden = true;
      linkedPanel.hidden = true;
      if (val.length > 0) {
        statusEl.textContent = "Not a valid device link.";
        statusEl.setAttribute("data-error", "1");
      } else {
        statusEl.textContent = "";
        statusEl.removeAttribute("data-error");
      }
      currentUri = "";
      return;
    }
    currentUri = val;
    statusEl.textContent = "Checking...";
    statusEl.removeAttribute("data-error");
    previewPanel.hidden = true;
    linkedPanel.hidden = true;
    void (async () => {
      try {
        const preview = await invoke<OfferPreview>("chat_preview_link_offer", { uri: val });
        if (currentUri !== val) return;
        if (preview.expired) {
          statusEl.textContent =
            "This link has expired. Ask the other device to generate a new one.";
          statusEl.setAttribute("data-error", "1");
          previewPanel.hidden = true;
          return;
        }
        statusEl.textContent = "";
        statusEl.removeAttribute("data-error");
        existingCode.textContent = preview.shortCode;
        confirmBtn.disabled = false;
        previewPanel.hidden = false;
      } catch (e) {
        if (currentUri !== val) return;
        statusEl.textContent = `Could not read link: ${String(e)}`;
        statusEl.setAttribute("data-error", "1");
        previewPanel.hidden = true;
      }
    })();
  });

  confirmBtn.addEventListener("click", () => {
    const uri = currentUri;
    if (!uri) return;
    confirmBtn.disabled = true;
    confirmBtn.textContent = "Linking...";
    statusEl.textContent = "";
    statusEl.removeAttribute("data-error");
    void (async () => {
      try {
        await invoke("chat_enroll_confirmed_device", { uri });
        previewPanel.hidden = true;
        linkedPanel.hidden = false;
        currentUri = "";
        confirmBtn.textContent = "Yes, link it";
      } catch (e) {
        statusEl.textContent = `Couldn’t link the device. ${friendlyError(e)}`;
        statusEl.setAttribute("data-error", "1");
        confirmBtn.disabled = false;
        confirmBtn.textContent = "Yes, link it";
      }
    })();
  });

  resetBtn.addEventListener("click", () => {
    uriInput.value = "";
    clearExisting();
  });

  // -- MODAL MECHANICS

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

  closeBtn.addEventListener("click", () => api.close());

  const api: LinkDeviceModalApi = {
    open() {
      host.hidden = false;
      document.addEventListener("keydown", onKey);
      host.addEventListener("click", onBackdrop);
      closeBtn.focus();
    },
    close() {
      host.hidden = true;
      document.removeEventListener("keydown", onKey);
      host.removeEventListener("click", onBackdrop);
    },
    isOpen: () => !host.hidden,
  };

  return api;
}
