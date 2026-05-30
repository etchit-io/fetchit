// Conversations list with presence dots + unread badges. Click a row
// to focus that conversation in the main pane.

import type { ChatStore, Conversation, NearbyPeer } from "./state";
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

  const nearbySection = document.createElement("section");
  nearbySection.className = "chat-nearby";
  nearbySection.hidden = true;

  root.appendChild(header);
  root.appendChild(list);
  root.appendChild(nearbySection);

  const render = (): void => {
    const convs = store.conversationsSorted();
    if (convs.length === 0) {
      list.replaceChildren(emptyState());
    } else {
      list.replaceChildren();
      const activeKey = store.active() ? convKey(store.active()!.key) : null;
      for (const conv of convs) {
        list.appendChild(rowFor(conv, store, activeKey, handlers.onSelect));
      }
    }
    renderNearby(nearbySection, store.nearbyPeersUnknown(), handlers.onNewContact);
  };

  const unsub = store.subscribe(render);
  render();
  return { dispose: unsub };
}

function renderNearby(
  host: HTMLElement,
  peers: NearbyPeer[],
  onAdd: () => void,
): void {
  if (peers.length === 0) {
    host.hidden = true;
    host.replaceChildren();
    return;
  }
  host.hidden = false;
  host.replaceChildren();

  const heading = document.createElement("h3");
  heading.className = "chat-nearby__heading";
  heading.textContent = "Nearby";
  host.appendChild(heading);

  const note = document.createElement("p");
  note.className = "chat-nearby__note";
  note.textContent =
    "Devices announcing on your network. Add via paste-URI to trust them.";
  host.appendChild(note);

  const ul = document.createElement("ul");
  ul.className = "chat-nearby__list";
  ul.setAttribute("role", "list");
  for (const peer of peers) {
    ul.appendChild(nearbyRow(peer, onAdd));
  }
  host.appendChild(ul);
}

function nearbyRow(peer: NearbyPeer, onAdd: () => void): HTMLElement {
  const li = document.createElement("li");
  li.className = "chat-nearby__row";

  const id = document.createElement("code");
  id.className = "chat-nearby__id";
  // Short prefix only — full agent_id is not user-meaningful and a
  // longer label would invite spoofed display names (TXT doesn't
  // carry one).
  id.textContent = `${peer.agentId.slice(0, 8)}…${peer.agentId.slice(-4)}`;
  id.title = peer.agentId;

  const meta = document.createElement("span");
  meta.className = "chat-nearby__meta";
  meta.textContent = `${peer.ip}:${peer.port}`;

  const addBtn = document.createElement("button");
  addBtn.type = "button";
  addBtn.className = "chat-nearby__add";
  addBtn.textContent = "Add";
  addBtn.title = "Open Add-contact dialog (you still paste their share URI)";
  addBtn.addEventListener("click", onAdd);

  li.appendChild(id);
  li.appendChild(meta);
  li.appendChild(addBtn);
  return li;
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
