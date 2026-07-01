// Group member list ("who is in this group"). Opened from the group
// conversation header; lists each active member by avatar + name. A
// member's name resolves the same way the who-is-who sender label does:
// the display name they joined with, else a saved-contact label, else a
// short agent id.

import {
  groupBanMember,
  groupInvite,
  groupMembers,
  groupRemoveMember,
  groupRename,
} from "./api";
import { avatarGradientClass, initials } from "./avatarColor";
import { chatConfirm } from "./confirmDialog";
import { friendlyError } from "./errors";
import type { ChatStore } from "./state";

export interface MemberListOpts {
  groupId: string;
  groupTitle: string;
  store: ChatStore;
  onClose: () => void;
  /// Called after a change that the rest of the app should pick up
  /// (rename, remove, ban) so the caller can refresh groups/roster.
  onChanged?: () => void;
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

  const load = async (): Promise<void> => {
    let members;
    try {
      members = await groupMembers(opts.groupId);
    } catch (e) {
      // Failure happens before any list mutation or handler binding, so
      // retrying re-runs the whole load safely.
      status.textContent = `Couldn't load members: ${friendlyError(e)} `;
      const retry = document.createElement("button");
      retry.type = "button";
      retry.className = "chat-dialog__btn";
      retry.textContent = "Retry";
      retry.addEventListener("click", () => {
        status.textContent = "Loading…";
        void load();
      });
      status.append(retry);
      return;
    }
    if (members.length === 0) {
      status.textContent = "No members yet.";
      return;
    }
    status.hidden = true;
    let count = members.length;
    let currentName = opts.groupTitle;
    const renderCount = (): void => {
      title.textContent = `In ${currentName} · ${count}`;
    };
    renderCount();

    // The viewer's own role decides whether moderation controls show;
    // x0xd is the real gate, this just hides controls that would 4xx.
    const myRole = members.find((m) => m.agent_id === me)?.role;
    const canModerate = myRole === "owner" || myRole === "admin";

    // Owner/admin: click the title to rename the group inline.
    if (canModerate) {
      title.classList.add("chat-members__title--editable");
      title.title = "Rename this group";
      title.addEventListener("click", () => {
        const input = document.createElement("input");
        input.type = "text";
        input.className = "chat-members__rename";
        input.value = currentName;
        title.replaceWith(input);
        input.focus();
        input.select();
        let done = false;
        const finish = (commit: boolean): void => {
          if (done) return;
          done = true;
          const next = input.value.trim();
          input.replaceWith(title);
          renderCount();
          if (!commit || next === "" || next === currentName) return;
          void (async () => {
            try {
              await groupRename(opts.groupId, next);
              currentName = next;
              renderCount();
              opts.onChanged?.();
            } catch (e) {
              status.hidden = false;
              status.textContent = `Couldn't rename: ${friendlyError(e)}`;
            }
          })();
        };
        input.addEventListener("keydown", (e) => {
          if (e.key === "Enter") finish(true);
          else if (e.key === "Escape") finish(false);
        });
        input.addEventListener("blur", () => finish(true));
      });
    }

    // Owner/admin: mint and share a fresh invite so more people can join
    // after the group already exists. groups().invite works on any group
    // the caller is in, not only at creation; x0xd is the real gate on
    // who may invite, mirroring the moderation gating above.
    if (canModerate) {
      const inviteBox = document.createElement("textarea");
      inviteBox.className = "chat-dialog__uri";
      inviteBox.readOnly = true;
      inviteBox.rows = 4;
      inviteBox.wrap = "soft";
      inviteBox.setAttribute("aria-label", "Invite link");
      inviteBox.hidden = true;
      inner.insertBefore(inviteBox, actions);

      const copyBtn = document.createElement("button");
      copyBtn.type = "button";
      copyBtn.className = "chat-dialog__btn";
      copyBtn.textContent = "Copy invite";
      copyBtn.hidden = true;
      copyBtn.addEventListener("click", () => {
        void navigator.clipboard.writeText(inviteBox.value).catch(() => {});
      });

      const inviteBtn = document.createElement("button");
      inviteBtn.type = "button";
      inviteBtn.className = "chat-dialog__btn";
      inviteBtn.textContent = "Invite someone";
      inviteBtn.addEventListener("click", () => {
        void (async () => {
          inviteBtn.disabled = true;
          const restore = inviteBtn.textContent;
          inviteBtn.textContent = "Creating invite…";
          try {
            inviteBox.value = await groupInvite(opts.groupId);
            inviteBox.hidden = false;
            copyBtn.hidden = false;
            status.hidden = false;
            status.textContent =
              "Share this link. They join when they paste it.";
            copyBtn.focus();
          } catch (e) {
            status.hidden = false;
            status.textContent = `Couldn't create invite: ${friendlyError(e)}`;
          } finally {
            inviteBtn.disabled = false;
            inviteBtn.textContent = restore;
          }
        })();
      });

      actions.insertBefore(inviteBtn, closeBtn);
      actions.insertBefore(copyBtn, closeBtn);
    }

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

      // An owner/admin may remove (kick) or ban any non-owner who is not
      // themselves. Both confirm; on success the row drops and the app
      // refreshes. Ban is the stronger action (blocks rejoin).
      if (canModerate && m.agent_id !== me && m.role !== "owner") {
        const moderate = (
          text: string,
          className: string,
          message: string,
          run: () => Promise<void>,
        ): HTMLButtonElement => {
          const btn = document.createElement("button");
          btn.type = "button";
          btn.className = className;
          btn.textContent = text;
          btn.title = `${text} ${name}`;
          btn.addEventListener("click", () => {
            void (async () => {
              const ok = await chatConfirm({
                title: `${text} member`,
                message,
                confirmLabel: text,
              });
              if (!ok) return;
              btn.disabled = true;
              try {
                await run();
                li.remove();
                count -= 1;
                renderCount();
                opts.onChanged?.();
              } catch (e) {
                btn.disabled = false;
                status.hidden = false;
                status.textContent =
                  `Couldn't ${text.toLowerCase()}: ${friendlyError(e)}`;
              }
            })();
          });
          return btn;
        };

        li.appendChild(moderate(
          "Remove",
          "chat-member__remove",
          `Remove ${name} from this group? They lose access to new messages.`,
          () => groupRemoveMember(opts.groupId, m.agent_id),
        ));
        li.appendChild(moderate(
          "Ban",
          "chat-member__remove chat-member__ban",
          `Ban ${name}? They are removed and cannot rejoin.`,
          () => groupBanMember(opts.groupId, m.agent_id),
        ));
      }

      list.appendChild(li);
    }
  };
  void load();
}
