// Add-contact dialog — accepts a pasted `x0x://agent/…` card URI and
// forwards it to the daemon's import endpoint.

import { importCard } from "./api";
import { errMsg } from "./errors";

export interface AddContactHandlers {
  onClose: () => void;
  onImported: () => void;
}

export function mountAddContact(
  root: HTMLElement,
  handlers: AddContactHandlers,
): void {
  root.replaceChildren();
  root.className = "chat-dialog";

  const inner = document.createElement("div");
  inner.className = "chat-dialog__panel";

  const title = document.createElement("h3");
  title.textContent = "Add a contact";

  const help = document.createElement("p");
  help.className = "chat-dialog__help";
  help.textContent
    = "Paste an x0x://agent/… card URI from someone you trust.";

  // Share URIs are long (KEM/ML-DSA keys + signature add up to ~17KB).
  // A single-line <input> forces the text engine to lay out the entire
  // value on one line and crashes the Wayland Cairo surface allocator
  // past 65535 px; textarea wraps visually and keeps the box bounded.
  const input = document.createElement("textarea");
  input.className = "chat-dialog__uri";
  input.placeholder = "x0x://agent/…";
  input.spellcheck = false;
  input.rows = 4;
  input.wrap = "soft";
  input.setAttribute("aria-label", "Card URI");

  const status = document.createElement("p");
  status.className = "chat-dialog__status";

  const actions = document.createElement("div");
  actions.className = "chat-dialog__actions";

  const addBtn = document.createElement("button");
  addBtn.type = "button";
  addBtn.className = "chat-dialog__btn";
  addBtn.textContent = "Add";
  addBtn.disabled = true;

  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "chat-dialog__btn chat-dialog__btn--ghost";
  closeBtn.textContent = "Cancel";
  closeBtn.addEventListener("click", handlers.onClose);

  actions.appendChild(addBtn);
  actions.appendChild(closeBtn);

  inner.appendChild(title);
  inner.appendChild(help);
  inner.appendChild(input);
  inner.appendChild(status);
  inner.appendChild(actions);
  root.appendChild(inner);

  root.addEventListener("click", (e) => {
    if (e.target === root) handlers.onClose();
  });

  input.addEventListener("input", () => {
    addBtn.disabled = !input.value.trim().startsWith("x0x://agent/");
    status.textContent = "";
  });

  addBtn.addEventListener("click", async () => {
    addBtn.disabled = true;
    status.textContent = "Importing…";
    try {
      await importCard(input.value.trim());
      status.textContent = "Imported.";
      handlers.onImported();
    } catch (e) {
      status.textContent = `Failed: ${errMsg(e)}`;
      addBtn.disabled = false;
    }
  });

  setTimeout(() => input.focus(), 0);
}
