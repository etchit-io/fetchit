// Slide-in chat panel — the top-level chat surface. Mounts the
// sidebar (conversation list) and the conversation pane side-by-side,
// wires the in-panel dialogs (share card, add contact), and bootstraps
// initial state from the daemon.

import {
  health,
  identity,
  listContacts,
  listGroups,
  presenceOnline,
} from "./api";
import { bindChatEvents } from "./events";
import { mountSidebar } from "./sidebar";
import { mountConversation } from "./conversation";
import { mountCardDialog } from "./contactCard";
import { mountAddContact } from "./addContact";
import { mountNewGroup } from "./newGroup";
import { ChatStore } from "./state";

export interface ChatPanelHandlers {
  onAutonomi: (addr: string) => void;
  onClose: () => void;
}

export interface ChatPanelApi {
  open(): Promise<void>;
  close(): void;
  toggle(): Promise<void>;
  isOpen(): boolean;
}

export function mountChatPanel(
  host: HTMLElement,
  handlers: ChatPanelHandlers,
): ChatPanelApi {
  host.replaceChildren();
  host.className = "chat-panel";
  host.hidden = true;

  const store = new ChatStore();
  const layout = document.createElement("div");
  layout.className = "chat-panel__layout";

  const headerEl = document.createElement("header");
  headerEl.className = "chat-panel__header";
  const titleEl = document.createElement("div");
  titleEl.className = "chat-panel__title";
  titleEl.textContent = "Chat";
  const idBadge = document.createElement("div");
  idBadge.className = "chat-panel__id";
  idBadge.textContent = "—";

  const shareBtn = document.createElement("button");
  shareBtn.type = "button";
  shareBtn.className = "chat-panel__share";
  shareBtn.textContent = "Share my card";

  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "chat-panel__close";
  closeBtn.setAttribute("aria-label", "Close chat");
  closeBtn.textContent = "✕";

  headerEl.appendChild(titleEl);
  headerEl.appendChild(idBadge);
  headerEl.appendChild(shareBtn);
  headerEl.appendChild(closeBtn);

  const sidebarEl = document.createElement("aside");
  const conversationEl = document.createElement("section");
  const dialogHost = document.createElement("div");
  dialogHost.hidden = true;

  layout.appendChild(sidebarEl);
  layout.appendChild(conversationEl);

  host.appendChild(headerEl);
  host.appendChild(layout);
  host.appendChild(dialogHost);

  const showDialog = (mount: (root: HTMLElement) => void): void => {
    dialogHost.hidden = false;
    mount(dialogHost);
  };
  const hideDialog = (): void => {
    dialogHost.hidden = true;
    dialogHost.replaceChildren();
  };

  const openShareCard = (): void => {
    const me = store.identity();
    const name = me?.user_id ?? `agent-${me?.agent_id.slice(0, 6) ?? "anon"}`;
    showDialog((root) => {
      void mountCardDialog(root, name, { onClose: hideDialog });
    });
  };

  const openAddContact = (): void => {
    showDialog((root) => {
      mountAddContact(root, {
        onClose: hideDialog,
        onImported: async () => {
          hideDialog();
          await refreshContacts();
        },
      });
    });
  };

  shareBtn.addEventListener("click", openShareCard);

  const openNewGroup = (): void => {
    const me = store.identity();
    const name = me?.user_id ?? `agent-${me?.agent_id.slice(0, 6) ?? "anon"}`;
    showDialog((root) => {
      mountNewGroup(root, name, {
        onClose: hideDialog,
        onCreated: () => {
          void refreshGroups();
        },
      });
    });
  };

  mountSidebar(sidebarEl, store, {
    onSelect: (conv) => {
      store.setActive(conv.key);
    },
    onNewContact: openAddContact,
    onNewGroup: openNewGroup,
  });

  mountConversation(conversationEl, store, {
    onAutonomi: (addr) => handlers.onAutonomi(addr),
    onCard: (uri) => {
      showDialog((root) => {
        mountAddContact(root, {
          onClose: hideDialog,
          onImported: () => {
            hideDialog();
            void refreshContacts();
          },
        });
        const input = root.querySelector<HTMLInputElement>(
          ".chat-dialog__uri",
        );
        if (input) {
          input.value = uri;
          input.dispatchEvent(new Event("input"));
        }
      });
    },
    onInvite: () => {
      // Group join lands with the group flow.
    },
    onAddContact: openAddContact,
  });

  const refreshContacts = async (): Promise<void> => {
    try {
      const [contacts, online] = await Promise.all([
        listContacts(),
        presenceOnline().catch(() => []),
      ]);
      store.loadContacts(contacts);
      store.loadPresence(online.map((a) => a.agent_id));
    } catch (e) {
      console.warn("[chat] contacts refresh failed:", e);
    }
  };

  const refreshGroups = async (): Promise<void> => {
    try {
      store.loadGroups(await listGroups());
    } catch (e) {
      console.warn("[chat] groups refresh failed:", e);
    }
  };

  let eventsBound = false;
  const open = async (): Promise<void> => {
    host.hidden = false;
    try {
      await health();
      const me = await identity();
      store.setIdentity(me);
      idBadge.textContent = `${me.agent_id.slice(0, 8)}…`;
      const [contacts, online, groups] = await Promise.all([
        listContacts(),
        presenceOnline(),
        listGroups().catch(() => []),
      ]);
      store.loadContacts(contacts);
      store.loadPresence(online.map((a) => a.agent_id));
      store.loadGroups(groups);
      if (!eventsBound) {
        eventsBound = true;
        await bindChatEvents(store);
      }
    } catch (e) {
      idBadge.textContent = "x0xd not running";
      console.warn("[chat] bootstrap failed:", e);
    }
  };

  const close = (): void => {
    host.hidden = true;
    hideDialog();
    handlers.onClose();
  };

  const api: ChatPanelApi = {
    open,
    close,
    isOpen: () => !host.hidden,
    async toggle() {
      if (host.hidden) await open();
      else close();
    },
  };

  closeBtn.addEventListener("click", () => {
    close();
  });

  return api;
}
