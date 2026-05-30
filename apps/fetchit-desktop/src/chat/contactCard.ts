// "Share your card" dialog — generates a fresh card from the daemon
// and displays the share URI + a QR. The user can rename themselves
// inline; saving regenerates the URI so the QR/copy buttons reflect
// the new label immediately.

import { myCard } from "./api";
import { errMsg } from "./errors";
import { renderQrSvg } from "../qr";

export interface CardDialogHandlers {
  onClose: () => void;
  /// Persist a user-typed display name. Called after the input loses
  /// focus or the user hits Enter. Resolves once settings is written.
  onRename: (name: string) => Promise<void>;
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

  const nameLabel = document.createElement("label");
  nameLabel.className = "chat-dialog__help";
  nameLabel.textContent = "Display name (visible to people you chat with)";

  const nameInput = document.createElement("input");
  nameInput.className = "chat-dialog__uri";
  nameInput.type = "text";
  nameInput.value = displayName;
  nameInput.spellcheck = false;
  nameInput.placeholder = "How you appear to others";
  nameInput.setAttribute("aria-label", "Display name");

  const status = document.createElement("p");
  status.className = "chat-dialog__status";
  status.textContent = "Generating…";

  const qrHost = document.createElement("div");
  qrHost.className = "chat-dialog__qr";
  qrHost.setAttribute("aria-hidden", "true");

  // Textarea (not input) so a multi-KB URI wraps visually — a
  // single-line input would force the text engine to lay out the
  // entire value on one line and crash the Wayland Cairo allocator.
  const uriBox = document.createElement("textarea");
  uriBox.className = "chat-dialog__uri";
  uriBox.readOnly = true;
  uriBox.rows = 4;
  uriBox.wrap = "soft";
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
  inner.appendChild(nameLabel);
  inner.appendChild(nameInput);
  inner.appendChild(status);
  inner.appendChild(qrHost);
  inner.appendChild(uriBox);
  inner.appendChild(actions);
  root.appendChild(inner);

  root.addEventListener("click", (e) => {
    if (e.target === root) handlers.onClose();
  });

  let currentName = displayName;

  const regenerate = async (name: string): Promise<void> => {
    status.textContent = "Generating…";
    qrHost.replaceChildren();
    uriBox.value = "";
    try {
      const result = await myCard(name);
      status.textContent = `${result.card.display_name} · ${result.card.agent_id.slice(0, 8)}…`;
      uriBox.value = result.uri;
      // QR is best-effort. v2 cards carry a KEM pubkey + sigs and
      // can exceed any QR version's capacity; in that case fall back
      // to a textual notice so the URI itself stays usable.
      try {
        qrHost.replaceChildren(renderQrSvg(result.uri));
      } catch {
        const notice = document.createElement("p");
        notice.className = "chat-dialog__help";
        notice.textContent = "URI too large for a QR — use Copy URI instead.";
        qrHost.replaceChildren(notice);
      }
    } catch (e) {
      status.textContent = `Could not generate card: ${errMsg(e)}`;
    }
  };

  const applyRename = async (): Promise<void> => {
    const next = nameInput.value.trim();
    if (next === currentName.trim()) return;
    currentName = next;
    try {
      await handlers.onRename(next);
    } catch (e) {
      console.warn("[chat] save display name:", e);
    }
    await regenerate(next);
  };

  nameInput.addEventListener("change", () => {
    void applyRename();
  });
  nameInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      nameInput.blur();
    }
  });

  copyBtn.addEventListener("click", async () => {
    if (!uriBox.value) return;
    try {
      await navigator.clipboard.writeText(uriBox.value);
      copyBtn.textContent = "Copied";
      setTimeout(() => {
        copyBtn.textContent = "Copy URI";
      }, 1200);
    } catch {
      uriBox.select();
      document.execCommand("copy");
    }
  });

  await regenerate(displayName);
}
