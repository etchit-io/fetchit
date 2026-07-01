// Conversations list with presence dots + unread badges. Click a row
// to focus that conversation in the main pane.

import type { ChatStore, Conversation, NearbyPeer } from "./state";
import { convKey } from "./state";
import { avatarGradientClass, initials } from "./avatarColor";
import { chatConfirm } from "./confirmDialog";
import { icon, mark, type IconName } from "../ui/icons";

export interface SidebarHandlers {
  onSelect: (conv: Conversation) => void;
  onNewContact: () => void;
  onNewGroup: () => void;
  onJoinGroup: () => void;
  /// Remove a DM from the list: deletes the contact + its local
  /// transcript. The sidebar confirms first.
  onRemoveContact: (agentId: string) => void;
  /// Leave a group from the list: leaves + drops the conversation. The
  /// sidebar confirms first.
  onLeaveGroup: (groupId: string) => void;
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
  actions.appendChild(iconButton("add-contact", "Add contact", handlers.onNewContact));
  actions.appendChild(iconButton("new-group", "New group", handlers.onNewGroup));
  actions.appendChild(iconButton("join-group", "Join group", handlers.onJoinGroup));
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
      // First-run onboarding carries its own actions, so the list is no
      // longer a listbox — drop the role so the buttons aren't trapped
      // as bogus options for assistive tech.
      list.removeAttribute("role");
      list.replaceChildren(onboarding(handlers));
    } else {
      list.setAttribute("role", "listbox");
      list.replaceChildren();
      const activeKey = store.active() ? convKey(store.active()!.key) : null;
      for (const conv of convs) {
        list.appendChild(rowFor(conv, store, activeKey, handlers));
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
    "People running Fetch on your local network. To chat with one, add "
    + "them like any contact — with their share link or QR code.";
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
  handlers: SidebarHandlers,
): HTMLElement {
  const li = document.createElement("li");
  li.className = "chat-conv";
  if (convKey(conv.key) === activeKey) li.classList.add("chat-conv--active");
  li.setAttribute("role", "option");
  li.tabIndex = 0;
  li.addEventListener("click", () => handlers.onSelect(conv));
  li.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      handlers.onSelect(conv);
    }
  });

  const avatar = document.createElement("span");
  avatar.className = "chat-conv__avatar";
  avatar.classList.add(
    avatarGradientClass(conv.key.kind === "dm" ? conv.key.peer : conv.key.groupId),
  );
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
  // M3 G2: flag a DM whose peer is on the community denylist. Group
  // conversations aren't agent-addressed so the indicator is DM-only.
  const blocked = conv.key.kind === "dm" && store.isDenylisted(conv.key.peer);
  if (blocked) {
    li.classList.add("chat-conv--blocked");
    const flag = document.createElement("span");
    flag.className = "chat-conv__blocked";
    flag.textContent = "⛔";
    flag.title = "On the community safety denylist";
    flag.setAttribute("aria-label", "blocked contact");
    titleRow.appendChild(flag);
  }
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

  // Per-row remove, revealed on hover/focus. Reachable from the list
  // itself so old chats and groups can be cleared without opening each
  // one and hunting for a menu. Destructive, so it always confirms.
  const isGroup = conv.key.kind === "group";
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "chat-conv__remove";
  const removeLabel = isGroup ? "Leave this group" : "Remove this chat";
  remove.title = removeLabel;
  remove.setAttribute("aria-label", removeLabel);
  remove.appendChild(icon("close"));
  remove.addEventListener("click", (e) => {
    // Don't let the click also select/open the conversation.
    e.stopPropagation();
    void (async () => {
      const ok = await chatConfirm(
        isGroup
          ? {
            title: "Leave group",
            message: `Leave "${conv.title}"? You'll need a new invite to rejoin.`,
            confirmLabel: "Leave",
          }
          : {
            title: "Remove chat",
            message:
              `Remove your chat with ${conv.title}? Its messages will be deleted from this device.`,
            confirmLabel: "Remove",
          },
      );
      if (!ok) return;
      if (conv.key.kind === "group") handlers.onLeaveGroup(conv.key.groupId);
      else handlers.onRemoveContact(conv.key.peer);
    })();
  });
  li.appendChild(remove);

  return li;
}

function iconButton(
  name: IconName,
  label: string,
  onClick: () => void,
): HTMLButtonElement {
  const b = document.createElement("button");
  b.className = "chat-icon-btn";
  b.type = "button";
  b.title = label;
  b.setAttribute("aria-label", label);
  b.appendChild(icon(name));
  b.addEventListener("click", onClick);
  return b;
}

// First-run / no-conversations state. Per the idiot-proof rules this is
// never a dead end: it names the app, says what to do in one plain
// sentence, and carries the single obvious next action as a big button.
function onboarding(handlers: SidebarHandlers): HTMLElement {
  const li = document.createElement("li");
  li.className = "chat-conv-empty";

  const spark = mark("lit", { label: "LIT Chat" });
  spark.classList.add("chat-onboard__mark");

  const title = document.createElement("div");
  title.className = "chat-conv-empty__title";
  title.textContent = "Welcome to LIT Chat";

  const body = document.createElement("div");
  body.className = "chat-conv-empty__body";
  body.textContent
    = "No conversations yet. Add someone you know and say hello.";

  const actions = document.createElement("div");
  actions.className = "chat-onboard__actions";

  const primary = document.createElement("button");
  primary.type = "button";
  primary.className = "chat-dialog__btn chat-onboard__primary";
  primary.appendChild(icon("add-contact"));
  primary.appendChild(document.createTextNode("Add your first person"));
  primary.addEventListener("click", handlers.onNewContact);

  const secondary = document.createElement("button");
  secondary.type = "button";
  secondary.className = "chat-dialog__btn chat-dialog__btn--ghost chat-onboard__secondary";
  secondary.textContent = "Create a group";
  secondary.addEventListener("click", handlers.onNewGroup);

  actions.appendChild(primary);
  actions.appendChild(secondary);

  li.appendChild(spark);
  li.appendChild(title);
  li.appendChild(body);
  li.appendChild(actions);
  return li;
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
