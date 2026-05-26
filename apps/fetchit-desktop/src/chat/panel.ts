// Slide-in chat panel — the top-level chat surface. Mounts the
// sidebar (conversation list) and the conversation pane side-by-side,
// wires the in-panel dialogs (share card, add contact), and bootstraps
// initial state from the daemon.

import {
  dmConnect,
  health,
  identity,
  listContacts,
  listGroups,
  presenceOnline,
  removeContact,
  sendDm,
  setTrust,
} from "./api";
import { startOutboxDriver } from "./outboxDriver";
import { bindChatEvents } from "./events";
import { mountSidebar } from "./sidebar";
import { mountConversation } from "./conversation";
import { mountCardDialog } from "./contactCard";
import { mountAddContact } from "./addContact";
import { mountNewGroup } from "./newGroup";
import { mountJoinGroup } from "./joinGroup";
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
  setDocked(docked: boolean): void;
  isDocked(): boolean;
}

const DOCK_KEY = "fetchit-chat:dock";

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

  const dockBtn = document.createElement("button");
  dockBtn.type = "button";
  dockBtn.className = "chat-panel__dock";
  dockBtn.setAttribute("aria-label", "Toggle dock");
  dockBtn.title = "Dock / undock";
  dockBtn.textContent = "▤";

  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "chat-panel__close";
  closeBtn.setAttribute("aria-label", "Close chat");
  closeBtn.textContent = "✕";

  headerEl.appendChild(titleEl);
  headerEl.appendChild(idBadge);
  headerEl.appendChild(shareBtn);
  headerEl.appendChild(dockBtn);
  headerEl.appendChild(closeBtn);

  const outboxBanner = document.createElement("div");
  outboxBanner.className = "chat-outbox-banner";
  outboxBanner.hidden = true;
  outboxBanner.setAttribute("role", "status");

  const outboxLabel = document.createElement("span");
  outboxLabel.className = "chat-outbox-banner__label";
  const outboxRetry = document.createElement("button");
  outboxRetry.type = "button";
  outboxRetry.className = "chat-outbox-banner__retry";
  outboxRetry.textContent = "Retry";
  outboxRetry.addEventListener("click", () => store.resetFailedRetryCounters());
  outboxBanner.appendChild(outboxLabel);
  outboxBanner.appendChild(outboxRetry);

  const sidebarEl = document.createElement("aside");
  const conversationEl = document.createElement("section");
  const dialogHost = document.createElement("div");
  dialogHost.hidden = true;

  layout.appendChild(sidebarEl);
  layout.appendChild(conversationEl);

  host.appendChild(headerEl);
  host.appendChild(outboxBanner);
  host.appendChild(layout);
  host.appendChild(dialogHost);

  const renderOutboxBanner = (): void => {
    const pending = store.pendingOutbound();
    if (pending.length === 0) {
      outboxBanner.hidden = true;
      return;
    }
    const failed = pending.filter((p) => p.bubble.status === "failed").length;
    const waiting = pending.length - failed;
    const parts: string[] = [];
    if (waiting > 0) parts.push(`${waiting} waiting to deliver`);
    if (failed > 0) parts.push(`${failed} undelivered`);
    outboxLabel.textContent = parts.join(" · ");
    outboxRetry.hidden = failed === 0;
    outboxBanner.hidden = false;
  };
  store.subscribe(renderOutboxBanner);

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

  const openJoinGroup = (initialUri?: string): void => {
    const me = store.identity();
    const name = me?.user_id ?? `agent-${me?.agent_id.slice(0, 6) ?? "anon"}`;
    showDialog((root) => {
      mountJoinGroup(
        root,
        name,
        {
          onClose: hideDialog,
          onJoined: (group) => {
            hideDialog();
            void refreshGroups();
            store.setActive({ kind: "group", groupId: group.group_id });
          },
        },
        initialUri,
      );
    });
  };

  mountSidebar(sidebarEl, store, {
    onSelect: (conv) => {
      store.setActive(conv.key);
    },
    onNewContact: openAddContact,
    onNewGroup: openNewGroup,
    onJoinGroup: () => openJoinGroup(),
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
    onInvite: (uri) => {
      openJoinGroup(uri);
    },
    onAddContact: openAddContact,
    onSetTrust: (agentId, level) => {
      void (async () => {
        try {
          await setTrust(agentId, level);
          await refreshContacts();
        } catch (e) {
          console.warn("[chat] set trust failed:", e);
        }
      })();
    },
    onRemoveContact: (agentId) => {
      void (async () => {
        try {
          await removeContact(agentId);
          store.clearDmTranscript(agentId);
          await refreshContacts();
        } catch (e) {
          console.warn("[chat] remove contact failed:", e);
        }
      })();
    },
  });

  const refreshContacts = async (): Promise<void> => {
    try {
      // Only refresh contacts here. Presence is seeded once at open() and
      // then driven exclusively by the SSE pump; calling loadPresence on
      // every contact action would clobber online-events the stream has
      // already delivered with a snapshot that may not yet reflect them.
      store.loadContacts(await listContacts());
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

  let docked = readDockPref();
  const applyDock = (): void => {
    host.classList.toggle("chat-panel--docked", docked);
    document.body.classList.toggle("chat-docked", docked && !host.hidden);
    dockBtn.title = docked ? "Undock" : "Dock to side";
  };
  applyDock();

  let eventsBound = false;
  let stalenessTimer: ReturnType<typeof setInterval> | null = null;
  let outboxStop: (() => void) | null = null;
  const startStalenessTick = (): void => {
    if (stalenessTimer !== null) return;
    // Re-render periodically so views age out stale beacons, AND
    // re-pull /presence/online so transitions dropped during an SSE
    // reconnect get reconciled instead of leaving the dot wrong until
    // the user reopens the panel.
    stalenessTimer = setInterval(() => {
      store.tickPresence();
      void (async () => {
        try {
          store.mergePresenceSnapshot(await presenceOnline());
        } catch {
          // ignore — staleness fallback will grey peers out anyway
        }
      })();
    }, 30_000);
  };
  const stopStalenessTick = (): void => {
    if (stalenessTimer !== null) {
      clearInterval(stalenessTimer);
      stalenessTimer = null;
    }
  };
  const open = async (): Promise<void> => {
    host.hidden = false;
    applyDock();
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
      store.loadPresence(online);
      store.loadGroups(groups);
      if (!eventsBound) {
        eventsBound = true;
        await bindChatEvents(store);
      }
      if (!outboxStop) {
        outboxStop = startOutboxDriver(store, { sendDm, connect: dmConnect });
      }
      startStalenessTick();
    } catch (e) {
      idBadge.textContent = "x0xd not running";
      console.warn("[chat] bootstrap failed:", e);
    }
  };

  const close = (): void => {
    host.hidden = true;
    document.body.classList.remove("chat-docked");
    stopStalenessTick();
    hideDialog();
    handlers.onClose();
  };

  const api: ChatPanelApi = {
    open,
    close,
    isOpen: () => !host.hidden,
    isDocked: () => docked,
    setDocked(next: boolean) {
      docked = next;
      writeDockPref(next);
      applyDock();
    },
    async toggle() {
      if (host.hidden) await open();
      else close();
    },
  };

  dockBtn.addEventListener("click", () => api.setDocked(!docked));
  closeBtn.addEventListener("click", () => close());

  return api;
}

function readDockPref(): boolean {
  try {
    return localStorage.getItem(DOCK_KEY) === "1";
  } catch {
    return false;
  }
}

function writeDockPref(v: boolean): void {
  try {
    localStorage.setItem(DOCK_KEY, v ? "1" : "0");
  } catch {
    // ignore
  }
}
