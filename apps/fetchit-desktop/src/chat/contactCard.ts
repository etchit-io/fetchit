// "Share your card" dialog — generates a fresh card from the daemon
// and displays the share URI + a QR. The user can copy either form.

import { myCard } from "./api";
import { renderQrSvg } from "../qr";

export interface CardDialogHandlers {
  onClose: () => void;
}

export async function mountCardDialog(
  root: HTMLElement,
  displayName: string,
  handlers: CardDialogHandlers,
): Promise<void> {
  root.replaceChildren();
  root.className = "chat-dialog";

  const inner = document.createElement("div");
  inner.className = "chat-dialog__panel";

  const title = document.createElement("h3");
  title.textContent = "Your share card";

  const status = document.createElement("p");
  status.className = "chat-dialog__status";
  status.textContent = "Generating…";

  const qrHost = document.createElement("div");
  qrHost.className = "chat-dialog__qr";
  qrHost.setAttribute("aria-hidden", "true");

  const uriBox = document.createElement("input");
  uriBox.className = "chat-dialog__uri";
  uriBox.readOnly = true;
  uriBox.setAttribute("aria-label", "Share URI");

  const actions = document.createElement("div");
  actions.className = "chat-dialog__actions";

  const copyBtn = document.createElement("button");
  copyBtn.type = "button";
  copyBtn.className = "chat-dialog__btn";
  copyBtn.textContent = "Copy URI";

  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "chat-dialog__btn chat-dialog__btn--ghost";
  closeBtn.textContent = "Close";
  closeBtn.addEventListener("click", handlers.onClose);

  actions.appendChild(copyBtn);
  actions.appendChild(closeBtn);

  inner.appendChild(title);
  inner.appendChild(status);
  inner.appendChild(qrHost);
  inner.appendChild(uriBox);
  inner.appendChild(actions);
  root.appendChild(inner);

  root.addEventListener("click", (e) => {
    if (e.target === root) handlers.onClose();
  });

  try {
    const result = await myCard(displayName);
    status.textContent = `${result.card.display_name} · ${result.card.agent_id.slice(0, 8)}…`;
    uriBox.value = result.uri;
    qrHost.replaceChildren(renderQrSvg(result.uri));
    copyBtn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(result.uri);
        copyBtn.textContent = "Copied";
        setTimeout(() => {
          copyBtn.textContent = "Copy URI";
        }, 1200);
      } catch {
        uriBox.select();
        document.execCommand("copy");
      }
    });
  } catch (e) {
    status.textContent = `Could not generate card: ${(e as Error).message}`;
  }
}
