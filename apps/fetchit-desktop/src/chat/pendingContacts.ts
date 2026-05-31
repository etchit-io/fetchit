// Pending TOFU contact-request dialog. Lists first-contact welcomes
// the user hasn't yet accepted, with Accept / Reject affordances.
//
// Accept → `chat_confirm_contact(groupIdHex)` flips the conversation's
//          trust_state to Confirmed; subsequent inbound DMs from the
//          same sender land normally in the conversation list.
// Reject → `chat_remove_contact(peerAgentId)` removes the contact row
//          on the backend; the pending entry is dropped from the
//          local store. Future welcomes from the same sender will
//          re-trigger TOFU (sender retried; user gets a second look).
//
// The dialog mirrors the locked-down sandboxing pattern of the other
// chat dialogs — body-mounted host, pre-styled-hidden discipline to
// dodge the webkit2gtk compositor wedge, textarea-not-input where any
// long string is rendered, and backdrop-click-to-close.

import { confirmContact, removeContact } from "./api";
import { errMsg } from "./errors";
import type { ChatStore, PendingContact } from "./state";

export interface PendingContactsHandlers {
  onClose: () => void;
}

export function mountPendingContactsDialog(
  root: HTMLElement,
  store: ChatStore,
  handlers: PendingContactsHandlers,
): void {
  root.replaceChildren();
  root.className = "chat-dialog";

  const inner = document.createElement("div");
  inner.className = "chat-dialog__panel";

  const title = document.createElement("h3");
  title.textContent = "Contact requests";

  const help = document.createElement("p");
  help.className = "chat-dialog__help";
  help.textContent
    = "These people sent you a first message but you haven't added them yet."
    + " Only accept if you recognise the agent id from a card they shared.";

  const list = document.createElement("div");
  list.className = "pending-contacts-list";

  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "chat-dialog__btn chat-dialog__btn--ghost";
  closeBtn.textContent = "Close";
  // Wrapped close — see definition below — also unwires the store
  // subscription so a hidden dialog doesn't keep re-rendering on
  // unrelated store mutations.

  const actions = document.createElement("div");
  actions.className = "chat-dialog__actions";
  actions.appendChild(closeBtn);

  inner.appendChild(title);
  inner.appendChild(help);
  inner.appendChild(list);
  inner.appendChild(actions);
  root.appendChild(inner);

  // Canonical close — runs unsub + observer.disconnect() before
  // calling the host-supplied onClose so the store doesn't keep
  // driving renders on a dismissed dialog.
  const close = (): void => {
    unsub();
    detachObserver.disconnect();
    handlers.onClose();
  };
  closeBtn.addEventListener("click", close);
  root.addEventListener("click", (e) => {
    if (e.target === root) close();
  });

  const render = (): void => {
    list.replaceChildren();
    const pending = store.allPendingContacts();
    if (pending.length === 0) {
      const empty = document.createElement("p");
      empty.className = "chat-dialog__help";
      empty.textContent = "No pending requests.";
      list.appendChild(empty);
      return;
    }
    for (const entry of pending) {
      list.appendChild(renderRow(entry, store));
    }
  };

  const unsub = store.subscribe(render);
  // Close from any wrapper logic should drop the subscription. The
  // panel-side `hideDialog` rewrites `dialogHost.innerHTML` which
  // detaches us from the DOM but doesn't run our cleanup — wire a
  // MutationObserver as a belt-and-braces unsub trigger.
  const detachObserver = new MutationObserver(() => {
    if (!root.isConnected || root.childElementCount === 0) {
      unsub();
      detachObserver.disconnect();
    }
  });
  detachObserver.observe(root, { childList: true });

  render();
}

function renderRow(entry: PendingContact, store: ChatStore): HTMLElement {
  const row = document.createElement("div");
  row.className = "pending-contact-row";
  row.dataset.groupId = entry.groupIdHex;

  const idEl = document.createElement("div");
  idEl.className = "pending-contact-row__id";
  idEl.textContent = `agent-${entry.peerAgentId.slice(0, 12)}…`;
  idEl.title = entry.peerAgentId;

  const fullEl = document.createElement("div");
  fullEl.className = "pending-contact-row__full";
  fullEl.textContent = entry.peerAgentId;

  const status = document.createElement("p");
  status.className = "chat-dialog__status";

  const acceptBtn = document.createElement("button");
  acceptBtn.type = "button";
  acceptBtn.className = "chat-dialog__btn";
  acceptBtn.textContent = "Accept";

  const rejectBtn = document.createElement("button");
  rejectBtn.type = "button";
  rejectBtn.className = "chat-dialog__btn chat-dialog__btn--ghost";
  rejectBtn.textContent = "Reject";

  const lockButtons = (locked: boolean): void => {
    acceptBtn.disabled = locked;
    rejectBtn.disabled = locked;
  };

  acceptBtn.addEventListener("click", async () => {
    lockButtons(true);
    status.textContent = "Accepting…";
    try {
      await confirmContact(entry.groupIdHex);
      store.removePendingContact(entry.groupIdHex);
    } catch (e) {
      status.textContent = `Failed: ${errMsg(e)}`;
      lockButtons(false);
    }
  });

  rejectBtn.addEventListener("click", async () => {
    lockButtons(true);
    status.textContent = "Rejecting…";
    try {
      await removeContact(entry.peerAgentId);
      store.removePendingContact(entry.groupIdHex);
    } catch (e) {
      status.textContent = `Failed: ${errMsg(e)}`;
      lockButtons(false);
    }
  });

  const buttons = document.createElement("div");
  buttons.className = "pending-contact-row__buttons";
  buttons.appendChild(acceptBtn);
  buttons.appendChild(rejectBtn);

  row.appendChild(idEl);
  row.appendChild(fullEl);
  row.appendChild(status);
  row.appendChild(buttons);
  return row;
}
