// "New group" dialog — names a group via the daemon's `chat_group_create`
// command, then immediately shows the generated `x0x://invite/…` URI
// for sharing.

import { createGroup, groupInvite } from "./api";
import { errMsg } from "./errors";

export interface NewGroupHandlers {
  onClose: () => void;
  onCreated: () => void;
}

export function mountNewGroup(
  root: HTMLElement,
  myDisplayName: string,
  handlers: NewGroupHandlers,
): void {
  root.replaceChildren();
  root.className = "chat-dialog";

  const inner = document.createElement("div");
  inner.className = "chat-dialog__panel";

  const title = document.createElement("h3");
  title.textContent = "New group";

  const help = document.createElement("p");
  help.className = "chat-dialog__help";
  help.textContent = "Name the group. You can invite members afterwards.";

  const nameInput = document.createElement("input");
  nameInput.className = "chat-dialog__uri";
  nameInput.placeholder = "Group name";
  nameInput.spellcheck = false;
  nameInput.setAttribute("aria-label", "Group name");

  const status = document.createElement("p");
  status.className = "chat-dialog__status";

  const inviteBox = document.createElement("input");
  inviteBox.className = "chat-dialog__uri";
  inviteBox.readOnly = true;
  inviteBox.placeholder = "Invite URI will appear here";
  inviteBox.setAttribute("aria-label", "Invite URI");
  inviteBox.hidden = true;

  const actions = document.createElement("div");
  actions.className = "chat-dialog__actions";

  const copyBtn = document.createElement("button");
  copyBtn.type = "button";
  copyBtn.className = "chat-dialog__btn";
  copyBtn.textContent = "Copy invite";
  copyBtn.hidden = true;

  const createBtn = document.createElement("button");
  createBtn.type = "button";
  createBtn.className = "chat-dialog__btn";
  createBtn.textContent = "Create";
  createBtn.disabled = true;

  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "chat-dialog__btn chat-dialog__btn--ghost";
  closeBtn.textContent = "Close";
  closeBtn.addEventListener("click", handlers.onClose);

  actions.appendChild(copyBtn);
  actions.appendChild(createBtn);
  actions.appendChild(closeBtn);

  inner.appendChild(title);
  inner.appendChild(help);
  inner.appendChild(nameInput);
  inner.appendChild(inviteBox);
  inner.appendChild(status);
  inner.appendChild(actions);
  root.appendChild(inner);

  root.addEventListener("click", (e) => {
    if (e.target === root) handlers.onClose();
  });

  nameInput.addEventListener("input", () => {
    createBtn.disabled = nameInput.value.trim().length === 0;
  });

  copyBtn.addEventListener("click", async () => {
    const invite = inviteBox.value;
    if (!invite) return;
    try {
      await navigator.clipboard.writeText(invite);
      copyBtn.textContent = "Copied";
      setTimeout(() => {
        copyBtn.textContent = "Copy invite";
      }, 1200);
    } catch {
      inviteBox.select();
      document.execCommand("copy");
    }
  });

  createBtn.addEventListener("click", async () => {
    const name = nameInput.value.trim();
    if (!name) return;
    createBtn.disabled = true;
    status.textContent = "Creating…";
    try {
      const group = await createGroup(name, myDisplayName);
      const invite = await groupInvite(group.group_id);
      // Swap into the post-create state: hide the name input + Create
      // button (the dialog has done its one job); show the invite,
      // the Copy button, and let the user close when ready.
      nameInput.hidden = true;
      createBtn.hidden = true;
      inviteBox.value = invite;
      inviteBox.hidden = false;
      copyBtn.hidden = false;
      title.textContent = `Group "${group.name ?? group.group_id.slice(0, 8)}" created`;
      help.textContent = "Share this invite with members. They'll join when they paste it.";
      status.textContent = "";
      handlers.onCreated();
      setTimeout(() => copyBtn.focus(), 0);
    } catch (e) {
      status.textContent = `Failed: ${errMsg(e)}`;
      createBtn.disabled = false;
    }
  });

  setTimeout(() => nameInput.focus(), 0);
}
