// Join-group dialog — pastes an `x0x://invite/…` URI and asks the
// daemon to join. Same shape as add-contact so both feel like one
// gesture: paste a URI, hit confirm.

import { joinGroup } from "./api";
import { friendlyError } from "./errors";
import type { Group } from "./types";

export interface JoinGroupHandlers {
  onClose: () => void;
  onJoined: (group: Group) => void;
  /**
   * A join that could not converge yet (owner offline) succeeded as a durable
   * `Pending` intent — NOT an error. The caller starts the resume pump so it
   * auto-completes when the owner returns. Optional for back-compat.
   */
  onPending?: (groupId: string) => void;
}

export function mountJoinGroup(
  root: HTMLElement,
  myDisplayName: string,
  handlers: JoinGroupHandlers,
  initialUri?: string,
): void {
  root.replaceChildren();
  root.className = "chat-dialog";

  const inner = document.createElement("div");
  inner.className = "chat-dialog__panel";

  const title = document.createElement("h3");
  title.textContent = "Join a group";

  const help = document.createElement("p");
  help.className = "chat-dialog__help";
  help.textContent
    = "Paste an x0x://invite/… URI from a group member.";

  // Textarea (not input) so a multi-KB invite URI wraps visually.
  const input = document.createElement("textarea");
  input.className = "chat-dialog__uri";
  input.placeholder = "Paste your group invite link";
  input.spellcheck = false;
  input.rows = 4;
  input.wrap = "soft";
  input.setAttribute("aria-label", "Invite URI");

  const status = document.createElement("p");
  status.className = "chat-dialog__status";

  const actions = document.createElement("div");
  actions.className = "chat-dialog__actions";

  const joinBtn = document.createElement("button");
  joinBtn.type = "button";
  joinBtn.className = "chat-dialog__btn";
  joinBtn.textContent = "Join";
  joinBtn.disabled = true;

  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "chat-dialog__btn chat-dialog__btn--ghost";
  closeBtn.textContent = "Cancel";
  closeBtn.addEventListener("click", handlers.onClose);

  actions.appendChild(joinBtn);
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

  const validate = (): void => {
    joinBtn.disabled = !input.value.trim().startsWith("x0x://invite/");
    status.textContent = "";
  };

  input.addEventListener("input", validate);

  joinBtn.addEventListener("click", async () => {
    const uri = input.value.trim();
    if (!uri.startsWith("x0x://invite/")) return;
    joinBtn.disabled = true;
    status.textContent = "Joining…";
    try {
      const outcome = await joinGroup(uri, myDisplayName);
      if (outcome.status === "converged") {
        const group = outcome.group;
        status.textContent = `Joined ${group.name ?? group.group_id.slice(0, 8)}.`;
        handlers.onJoined(group);
      } else {
        // Pending: the owner is not reachable yet. This is NOT a failure — the
        // join is a durable intent the resume pump completes on its own, so we
        // reassure instead of showing the scary "Failed" the offline-owner
        // case used to hit.
        status.textContent
          = "Joining… this finishes on its own when the owner is back online.";
        handlers.onPending?.(outcome.group_id);
      }
    } catch (e) {
      status.textContent = `Failed: ${friendlyError(e)}`;
      joinBtn.disabled = false;
    }
  });

  if (initialUri) {
    input.value = initialUri;
    validate();
  }
  setTimeout(() => input.focus(), 0);
}
