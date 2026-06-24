// Group member list ("who is in this group"). Opened from the group
// conversation header; lists each active member by avatar + name. A
// member's name resolves the same way the who-is-who sender label does:
// the display name they joined with, else a saved-contact label, else a
// short agent id.

import { groupMembers, groupRemoveMember } from "./api";
import { avatarGradientClass, initials } from "./avatarColor";
import { chatConfirm } from "./confirmDialog";
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
    let count = members.length;
    const renderCount = (): void => {
      title.textContent = `In ${opts.groupTitle} · ${count}`;
    };
    renderCount();

    // The viewer's own role decides whether moderation controls show;
    // x0xd is the real gate, this just hides controls that would 4xx.
    const myRole = members.find((m) => m.agent_id === me)?.role;
    const canModerate = myRole === "owner" || myRole === "admin";

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

      if (m.role === "owner" || m.role === "admin") {
        const tag = document.createElement("span");
        tag.className = "chat-member__role";
        tag.textContent = m.role;
        li.appendChild(tag);
      }

      // An owner/admin may remove any non-owner who is not themselves.
      if (canModerate && m.agent_id !== me && m.role !== "owner") {
        const remove = document.createElement("button");
        remove.type = "button";
        remove.className = "chat-member__remove";
        remove.textContent = "Remove";
        remove.title = `Remove ${name} from the group`;
        remove.addEventListener("click", () => {
          void (async () => {
            const ok = await chatConfirm({
              title: "Remove member",
              message:
                `Remove ${name} from this group? They lose access to new messages.`,
              confirmLabel: "Remove",
            });
            if (!ok) return;
            remove.disabled = true;
            try {
              await groupRemoveMember(opts.groupId, m.agent_id);
              li.remove();
              count -= 1;
              renderCount();
            } catch (e) {
              remove.disabled = false;
              status.hidden = false;
              status.textContent = `Couldn't remove: ${friendlyError(e)}`;
            }
          })();
        });
        li.appendChild(remove);
      }

      list.appendChild(li);
    }
  })();
}
