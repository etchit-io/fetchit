// Conversations list with presence dots + unread badges. Click a row
// to focus that conversation in the main pane.

import type { ChatStore, Conversation } from "./state";
import { convKey } from "./state";

export interface SidebarHandlers {
  onSelect: (conv: Conversation) => void;
  onNewContact: () => void;
  onNewGroup: () => void;
  onJoinGroup: () => void;
}

export function mountSidebar(
  root: HTMLElement,
  store: ChatStore,
  handlers: SidebarHandlers,
): { dispose: () => void } {
  root.replaceChildren();
  root.className = "chat-sidebar";

  const header = document.createElement("div");
  header.className = "chat-sidebar__header";
  const title = document.createElement("h2");
  title.textContent = "Conversations";
  header.appendChild(title);

  const actions = document.createElement("div");
  actions.className = "chat-sidebar__actions";
  actions.appendChild(iconButton("＋", "Add contact", handlers.onNewContact));
  actions.appendChild(iconButton("⌗", "New group", handlers.onNewGroup));
  actions.appendChild(iconButton("↪", "Join group", handlers.onJoinGroup));
  header.appendChild(actions);

  const list = document.createElement("ul");
  list.className = "chat-conv-list";
  list.setAttribute("role", "listbox");

  root.appendChild(header);
  root.appendChild(list);

  const render = (): void => {
    const convs = store.conversationsSorted();
    if (convs.length === 0) {
      list.replaceChildren(emptyState());
      return;
    }
    list.replaceChildren();
    const activeKey = store.active() ? convKey(store.active()!.key) : null;
    for (const conv of convs) {
      list.appendChild(rowFor(conv, store, activeKey, handlers.onSelect));
    }
  };

  const unsub = store.subscribe(render);
  render();
  return { dispose: unsub };
}

function rowFor(
  conv: Conversation,
  store: ChatStore,
  activeKey: string | null,
  onSelect: (c: Conversation) => void,
): HTMLElement {
  const li = document.createElement("li");
  li.className = "chat-conv";
  if (convKey(conv.key) === activeKey) li.classList.add("chat-conv--active");
  li.setAttribute("role", "option");
  li.tabIndex = 0;
  li.addEventListener("click", () => onSelect(conv));
  li.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onSelect(conv);
    }
  });

  const avatar = document.createElement("span");
  avatar.className = "chat-conv__avatar";
  avatar.textContent = initials(conv.title);
  if (conv.key.kind === "dm" && store.isOnline(conv.key.peer)) {
    avatar.classList.add("chat-conv__avatar--online");
  }

  const body = document.createElement("div");
  body.className = "chat-conv__body";

  const titleRow = document.createElement("div");
  titleRow.className = "chat-conv__title-row";
  const title = document.createElement("span");
  title.className = "chat-conv__title";
  title.textContent = conv.title;
  const ts = document.createElement("time");
  ts.className = "chat-conv__ts";
  ts.textContent = relativeShort(conv.lastActivityMs);
  titleRow.appendChild(title);
  titleRow.appendChild(ts);

  const preview = document.createElement("div");
  preview.className = "chat-conv__preview";
  const last = conv.messages[conv.messages.length - 1];
  preview.textContent = last ? last.body : "—";

  body.appendChild(titleRow);
  body.appendChild(preview);

  li.appendChild(avatar);
  li.appendChild(body);

  if (conv.unread > 0) {
    const badge = document.createElement("span");
    badge.className = "chat-conv__unread";
    badge.textContent = conv.unread > 99 ? "99+" : String(conv.unread);
    li.appendChild(badge);
  }

  return li;
}

function iconButton(
  glyph: string,
  label: string,
  onClick: () => void,
): HTMLButtonElement {
  const b = document.createElement("button");
  b.className = "chat-icon-btn";
  b.type = "button";
  b.title = label;
  b.setAttribute("aria-label", label);
  b.textContent = glyph;
  b.addEventListener("click", onClick);
  return b;
}

function emptyState(): HTMLElement {
  const li = document.createElement("li");
  li.className = "chat-conv-empty";
  const title = document.createElement("div");
  title.className = "chat-conv-empty__title";
  title.textContent = "No conversations yet";
  const body = document.createElement("div");
  body.className = "chat-conv-empty__body";
  body.textContent = "Add a contact's card to start a DM, or create a group.";
  li.appendChild(title);
  li.appendChild(body);
  return li;
}

function initials(name: string): string {
  const parts = name.trim().split(/\s+/);
  if (parts.length === 0) return "?";
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[1][0]).toUpperCase();
}

function relativeShort(ms: number): string {
  if (!ms) return "";
  const diff = Date.now() - ms;
  if (diff < 60_000) return "now";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h`;
  if (diff < 7 * 86_400_000) return `${Math.floor(diff / 86_400_000)}d`;
  return new Date(ms).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
  });
}
