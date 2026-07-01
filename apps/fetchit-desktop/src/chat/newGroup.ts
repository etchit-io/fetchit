// "New group" dialog — names a group via the daemon's `chat_group_create`
// command, then immediately shows the generated `x0x://invite/…` URI
// for sharing.

import { createGroup, groupInvite } from "./api";
import type { CreateGroupPreset } from "./api";
import { friendlyError } from "./errors";

function makePresetRadio(
  value: CreateGroupPreset,
  labelText: string,
  detailText: string,
  checked: boolean,
): HTMLLabelElement {
  const label = document.createElement("label");
  label.className = "chat-dialog__radio";
  const input = document.createElement("input");
  input.type = "radio";
  input.name = "group-preset";
  input.value = value;
  input.checked = checked;
  label.appendChild(input);
  const text = document.createElement("span");
  text.className = "chat-dialog__radio-text";
  const strong = document.createElement("strong");
  strong.textContent = labelText;
  text.appendChild(strong);
  const detail = document.createElement("small");
  detail.className = "chat-dialog__radio-detail";
  detail.textContent = detailText;
  text.appendChild(detail);
  label.appendChild(text);
  return label;
}

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

  // Group id from a successful create, so the post-create "New invite"
  // button can mint a FRESH single-use invite per invitee. x0xd invites
  // are single-use (the owner consumes the secret on apply), so one invite
  // admits only the first joiner -- each member needs their own.
  let createdGroupId: string | null = null;

  const inner = document.createElement("div");
  inner.className = "chat-dialog__panel";

  const title = document.createElement("h3");
  title.textContent = "New group";

  const help = document.createElement("p");
  help.className = "chat-dialog__help";
  help.textContent = "Name the group. You can invite members afterwards.";

  const presetFieldset = document.createElement("fieldset");
  presetFieldset.className = "chat-dialog__fieldset";
  const presetLegend = document.createElement("legend");
  presetLegend.textContent = "Group type";
  presetFieldset.appendChild(presetLegend);
  presetFieldset.appendChild(makePresetRadio(
    "private_secure",
    "Private group",
    "PQ-encrypted via x0x MLS — only members can read.",
    true,
  ));
  presetFieldset.appendChild(makePresetRadio(
    "public_open",
    "Public room",
    "Plaintext on relay — see security docs before using.",
    false,
  ));

  const nameInput = document.createElement("input");
  nameInput.className = "chat-dialog__uri";
  nameInput.placeholder = "Group name";
  nameInput.spellcheck = false;
  nameInput.setAttribute("aria-label", "Group name");

  const status = document.createElement("p");
  status.className = "chat-dialog__status";

  // Textarea (not input) so a multi-KB invite URI wraps visually.
  const inviteBox = document.createElement("textarea");
  inviteBox.className = "chat-dialog__uri";
  inviteBox.readOnly = true;
  inviteBox.rows = 4;
  inviteBox.wrap = "soft";
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

  // Each press mints a FRESH single-use invite for the next person, so a
  // group can grow past two members. Shown after the group is created.
  const newInviteBtn = document.createElement("button");
  newInviteBtn.type = "button";
  newInviteBtn.className = "chat-dialog__btn";
  newInviteBtn.textContent = "New invite";
  newInviteBtn.hidden = true;

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
  actions.appendChild(newInviteBtn);
  actions.appendChild(createBtn);
  actions.appendChild(closeBtn);

  inner.appendChild(title);
  inner.appendChild(help);
  inner.appendChild(presetFieldset);
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

  function getSelectedPreset(): CreateGroupPreset {
    const checked = inner.querySelector<HTMLInputElement>(
      'input[name="group-preset"]:checked',
    );
    return checked?.value === "public_open" ? "public_open" : "private_secure";
  }

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

  newInviteBtn.addEventListener("click", async () => {
    if (!createdGroupId) return;
    newInviteBtn.disabled = true;
    status.textContent = "Generating a fresh invite…";
    try {
      const invite = await groupInvite(createdGroupId);
      inviteBox.value = invite;
      copyBtn.textContent = "Copy invite";
      status.textContent = "Fresh invite ready. Send it to one more person.";
      setTimeout(() => copyBtn.focus(), 0);
    } catch (e) {
      status.textContent = `Failed: ${friendlyError(e)}`;
    } finally {
      newInviteBtn.disabled = false;
    }
  });

  createBtn.addEventListener("click", async () => {
    const name = nameInput.value.trim();
    if (!name) return;
    const preset = getSelectedPreset();
    createBtn.disabled = true;
    status.textContent = "Creating…";
    try {
      const group = await createGroup(name, myDisplayName, preset);
      const invite = await groupInvite(group.group_id);
      // Swap into the post-create state: hide the name input + Create
      // button (the dialog has done its one job); show the invite,
      // the Copy button, and let the user close when ready.
      nameInput.hidden = true;
      presetFieldset.hidden = true;
      createBtn.hidden = true;
      createdGroupId = group.group_id;
      inviteBox.value = invite;
      inviteBox.hidden = false;
      copyBtn.hidden = false;
      newInviteBtn.hidden = false;
      const label = group.name ?? group.group_id.slice(0, 8);
      title.textContent
        = preset === "private_secure"
          ? `Group "${label}" created — PQ-encrypted via x0x MLS`
          : `Group "${label}" created — public room (plaintext on relay)`;
      help.textContent = "Each invite is single-use, so send every person their own. Tap New invite for the next member.";
      status.textContent = "";
      handlers.onCreated();
      setTimeout(() => copyBtn.focus(), 0);
    } catch (e) {
      status.textContent = `Failed: ${friendlyError(e)}`;
      createBtn.disabled = false;
    }
  });

  setTimeout(() => nameInput.focus(), 0);
}
