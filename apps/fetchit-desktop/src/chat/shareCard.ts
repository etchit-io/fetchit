// "Share my code" dialog — the primary pairing surface, and where you
// set your display name.
//
// Sets your name (so contacts see a name, not an id), then republishes
// the local reachability (pair) record to the relay and renders the
// QR-sized pointer URI (`x0x://pair/<id>?r=<relay>`) as copyable text
// plus a QR. The republish-before-render gate means a shared URI never
// 404s on the recipient's import: a "Publishing…" state shows until the
// record is confirmed live, then an honest offline error if the relay
// can't be reached.
//
// The v2 extended-card URI (the large offline/fallback payload) is no
// longer offered here — it lives under Settings → Advanced.

import { getDisplayName, pairShareUri, setDisplayName } from "./api";
import { friendlyError } from "./errors";
import { renderQrSvg } from "../qr";

export interface ShareCardHandlers {
  /// The user's own agent id, shown for verification (anti-impersonation).
  agentId: string;
  onClose: () => void;
  /// Called after the display name is saved, so the caller can reflect it
  /// (header badge, outbound sends) without re-opening.
  onNameSaved?: (name: string) => void;
}

export function mountShareCard(
  root: HTMLElement,
  handlers: ShareCardHandlers,
): void {
  root.replaceChildren();
  root.className = "chat-dialog";

  const inner = document.createElement("div");
  inner.className = "chat-dialog__panel";

  const title = document.createElement("h3");
  title.textContent = "Share my code";

  // Your name — set it here so contacts see a name, not an id. Saved on
  // blur or Enter; the caller updates the header badge via onNameSaved.
  const nameLabel = document.createElement("label");
  nameLabel.className = "chat-dialog__field-label";
  nameLabel.textContent = "Your name";
  const nameInput = document.createElement("input");
  nameInput.type = "text";
  nameInput.className = "chat-dialog__name";
  nameInput.placeholder = "Set a name so people know who you are";
  nameInput.maxLength = 64;
  nameInput.spellcheck = false;
  nameLabel.appendChild(nameInput);
  void getDisplayName()
    .then((n) => {
      if (inner.isConnected) nameInput.value = n;
    })
    .catch(() => {});
  let lastSaved: string | null = null;
  const saveName = (): void => {
    const next = nameInput.value.trim();
    if (next === lastSaved) return;
    lastSaved = next;
    void (async () => {
      try {
        await setDisplayName(next);
        handlers.onNameSaved?.(next);
      } catch (e) {
        console.warn("[chat] set name failed:", e);
      }
    })();
  };
  nameInput.addEventListener("blur", saveName);
  nameInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      nameInput.blur();
    }
  });

  const help = document.createElement("p");
  help.className = "chat-dialog__help";
  help.textContent
    = "Scan this code or copy the link to add you. It points your contacts at "
    + "your relay so they always reach you, even after you switch regions.";

  const status = document.createElement("p");
  status.className = "chat-dialog__status";
  status.textContent = "Publishing…";

  const qrHost = document.createElement("div");
  qrHost.className = "chat-dialog__qr";
  qrHost.setAttribute("aria-hidden", "true");

  // Textarea so a copied URI wraps visually; the pointer URI is short
  // (<= 512 bytes) but the box matches the rest of the chat dialogs.
  const uriBox = document.createElement("textarea");
  uriBox.className = "chat-dialog__uri";
  uriBox.readOnly = true;
  uriBox.rows = 3;
  uriBox.wrap = "soft";
  uriBox.setAttribute("aria-label", "Share URI");

  // Your full id, for verifying it's really you (anti-impersonation). Out
  // of the main flow but reachable: monospace + selectable to compare.
  const idRow = document.createElement("p");
  idRow.className = "chat-dialog__idrow";
  const idLabel = document.createElement("span");
  idLabel.textContent = "Your ID ";
  const idValue = document.createElement("code");
  idValue.className = "chat-dialog__idval";
  idValue.textContent = handlers.agentId;
  idRow.title = "Share this so people can verify it is really you.";
  idRow.append(idLabel, idValue);

  const actions = document.createElement("div");
  actions.className = "chat-dialog__actions";

  const copyBtn = document.createElement("button");
  copyBtn.type = "button";
  copyBtn.className = "chat-dialog__btn";
  copyBtn.textContent = "Copy link";
  copyBtn.disabled = true;

  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "chat-dialog__btn chat-dialog__btn--ghost";
  closeBtn.textContent = "Close";
  closeBtn.addEventListener("click", () => {
    // Save any pending name edit before the dialog goes away.
    saveName();
    handlers.onClose();
  });

  actions.appendChild(copyBtn);
  actions.appendChild(closeBtn);

  inner.appendChild(title);
  inner.appendChild(nameLabel);
  inner.appendChild(help);
  inner.appendChild(status);
  inner.appendChild(qrHost);
  inner.appendChild(uriBox);
  inner.appendChild(idRow);
  inner.appendChild(actions);
  root.appendChild(inner);

  root.addEventListener("click", (e) => {
    if (e.target === root) {
      saveName();
      handlers.onClose();
    }
  });

  copyBtn.addEventListener("click", async () => {
    if (!uriBox.value) return;
    try {
      await navigator.clipboard.writeText(uriBox.value);
      copyBtn.textContent = "Copied";
      setTimeout(() => {
        copyBtn.textContent = "Copy link";
      }, 1200);
    } catch {
      uriBox.select();
      document.execCommand("copy");
    }
  });

  // Republish + fetch the pointer URI. On success render it; on failure
  // show an honest "you're offline" state and leave nothing shareable —
  // a URI that didn't publish would 404 on the other side.
  void (async () => {
    try {
      const uri = await pairShareUri();
      // The dialog host is reused across dialogs (panel.ts hideDialog
      // replaceChildren detaches `inner`); a late resolve must not write
      // to detached nodes.
      if (!inner.isConnected) return;
      status.textContent = "Ready to share.";
      uriBox.value = uri;
      copyBtn.disabled = false;
      // Dark modules on the white panel so the code is crisp and
      // scannable (the default currentColor inherits the dialog's muted
      // text color, which washes the code out).
      qrHost.replaceChildren(renderQrSvg(uri, { foreground: "#1a1714" }));
    } catch (e) {
      if (!inner.isConnected) return;
      status.textContent
        = `You're offline — couldn't publish your card. ${friendlyError(e)}`;
      uriBox.value = "";
      copyBtn.disabled = true;
      qrHost.replaceChildren();
    }
  })();
}
