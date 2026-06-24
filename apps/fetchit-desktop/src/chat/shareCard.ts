// "Share my card" dialog — the primary pairing surface.
//
// Republishes the local reachability (pair) record to the relay, then
// renders the QR-sized pointer URI (`x0x://pair/<id>?r=<relay>`) as
// copyable text plus a QR. The republish-before-render gate means a
// shared URI never 404s on the recipient's import: the dialog shows a
// "Publishing…" state until the record is confirmed live, and an honest
// offline error if the relay can't be reached.
//
// The v2 extended-card URI (the large offline/fallback payload) is no
// longer offered here — it lives under Settings → Advanced.

import { pairShareUri } from "./api";
import { friendlyError } from "./errors";
import { renderQrSvg } from "../qr";

export interface ShareCardHandlers {
  onClose: () => void;
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
  closeBtn.addEventListener("click", handlers.onClose);

  actions.appendChild(copyBtn);
  actions.appendChild(closeBtn);

  inner.appendChild(title);
  inner.appendChild(help);
  inner.appendChild(status);
  inner.appendChild(qrHost);
  inner.appendChild(uriBox);
  inner.appendChild(actions);
  root.appendChild(inner);

  root.addEventListener("click", (e) => {
    if (e.target === root) handlers.onClose();
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
      qrHost.replaceChildren(renderQrSvg(uri));
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
