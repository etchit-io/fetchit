// Group member list ("who is in this group"). Opened from the group
// conversation header; lists each active member by avatar + name. A
// member's name resolves the same way the who-is-who sender label does:
// the display name they joined with, else a saved-contact label, else a
// short agent id.

import { groupMembers } from "./api";
import { avatarGradientClass, initials } from "./avatarColor";
import { friendlyError } from "./errors";
import type { ChatStore } from "./state";

export interface MemberListOpts {
  groupId: string;
  groupTitle: string;
  store: ChatStore;
  onClose: () => void;
}

/// Resolve a member's display name: the name they joined with (from the
/// daemon), else a saved-contact label, else a short agent id.
export function memberDisplayName(
  store: ChatStore,
  agentId: string,
  wireName?: string | null,
): string {
  const w = wireName?.trim();
  if (w) return w;
  const resolved = store.displayNameFor(agentId);
  if (resolved) return resolved;
  return `${agentId.slice(0, 8)}…`;
}

export function mountMemberList(root: HTMLElement, opts: MemberListOpts): void {
  root.replaceChildren();
  root.className = "chat-dialog";

  const inner = document.createElement("div");
  inner.className = "chat-dialog__panel";

  const title = document.createElement("h3");
  title.textContent = `In ${opts.groupTitle}`;

  const status = document.createElement("p");
  status.className = "chat-dialog__status";
  status.textContent = "Loading…";

  const list = document.createElement("ul");
  list.className = "chat-members";
  list.setAttribute("role", "list");

  const actions = document.createElement("div");
  actions.className = "chat-dialog__actions";
  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "chat-dialog__btn chat-dialog__btn--ghost";
  closeBtn.textContent = "Close";
  closeBtn.addEventListener("click", opts.onClose);
  actions.appendChild(closeBtn);

  inner.appendChild(title);
  inner.appendChild(status);
  inner.appendChild(list);
  inner.appendChild(actions);
  root.appendChild(inner);

  root.addEventListener("click", (e) => {
    if (e.target === root) opts.onClose();
  });

  const me = opts.store.myId();

  void (async () => {
    let members;
    try {
      members = await groupMembers(opts.groupId);
    } catch (e) {
      status.textContent = `Couldn't load members: ${friendlyError(e)}`;
      return;
    }
    if (members.length === 0) {
      status.textContent = "No members yet.";
      return;
    }
    status.hidden = true;
    title.textContent = `In ${opts.groupTitle} · ${members.length}`;
    for (const m of members) {
      const li = document.createElement("li");
      li.className = "chat-member";

      const avatar = document.createElement("span");
      avatar.className = "chat-member__avatar";
      avatar.classList.add(avatarGradientClass(m.agent_id));
      const name = memberDisplayName(opts.store, m.agent_id, m.display_name);
      avatar.textContent = initials(name);

      const label = document.createElement("span");
      label.className = "chat-member__name";
      label.textContent = m.agent_id === me ? `${name} (you)` : name;

      li.appendChild(avatar);
      li.appendChild(label);
      list.appendChild(li);
    }
  })();
}
