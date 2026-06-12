// Slide-in chat panel — the top-level chat surface. Mounts the
// sidebar (conversation list) and the conversation pane side-by-side,
// wires the in-panel dialogs (share card, add contact), and bootstraps
// initial state from the daemon.

import {
  dmConnect,
  getDisplayName,
  health,
  identity,
  leaveGroup,
  listContacts,
  listGroups,
  presenceOnline,
  removeContact,
  sendDm,
  setTrust,
  unwatchPresence,
  watchPresence,
} from "./api";
import { startOutboxDriver, type OutboxDriver } from "./outboxDriver";
import { bindChatEvents } from "./events";
import { classifyBootstrapError, renderChatUnavailableCard } from "./unavailableCard";
import { mountSidebar } from "./sidebar";
import { mountConversation } from "./conversation";
import { mountShareCard } from "./shareCard";
import { mountAddContact } from "./addContact";
import { mountNewGroup } from "./newGroup";
import { mountJoinGroup } from "./joinGroup";
import { mountPendingContactsDialog } from "./pendingContacts";
import { ChatStore } from "./state";
import { mark } from "../ui/icons";

export interface ChatPanelHandlers {
  onAutonomi: (addr: string) => void;
  onClose: () => void;
  /// Fires whenever the unread-count rolls up — used by the header
  /// chat button to badge itself. Receives the total across all DMs.
  onUnreadChange?: (count: number) => void;
}

export interface ChatPanelApi {
  open(): Promise<void>;
  close(): void;
  toggle(): Promise<void>;
  isOpen(): boolean;
  setDocked(docked: boolean): void;
  isDocked(): boolean;
  /// Open the panel focused on the DM with `agentIdHex` (the contact
  /// must already exist; the fediverse lookup imports before calling).
  openDm(agentIdHex: string): Promise<void>;
}

const DOCK_KEY = "fetchit-chat:dock";

/// Wait between bootstrap retries when `open()` throws partway —
/// matches the x0xd supervisor's poll cadence (`spawn_x0xd_supervisor`
/// in src-tauri/src/chat.rs) so a daemon coming back up is picked up
/// in the same window.
const BOOTSTRAP_RETRY_MS = 5_000;

export function mountChatPanel(
  host: HTMLElement,
  handlers: ChatPanelHandlers,
): ChatPanelApi {
  host.replaceChildren();
  host.className = "chat-panel";
  host.hidden = true;

  const store = new ChatStore();
  // User-chosen display name, persisted in settings. Used for outbound
  // share cards, group create/join, and the `sender_name` on DMs.
  // Empty string = unset; callers fall back to `me.user_id` then to
  // `agent-<6-hex>` so an unconfigured peer still has *something*
  // legible on the wire.
  let displayName = "";
  const resolveName = (): string => {
    if (displayName.trim() !== "") return displayName.trim();
    const me = store.identity();
    return me?.user_id ?? `agent-${me?.agent_id.slice(0, 6) ?? "anon"}`;
  };
  const layout = document.createElement("div");
  layout.className = "chat-panel__layout";

  const headerEl = document.createElement("header");
  headerEl.className = "chat-panel__header";
  // LIT Chat brand mark, leftmost in the header. Decorative; the
  // adjacent title text carries the accessible name.
  const litMark = mark("lit");
  litMark.classList.add("chat-panel__mark");
  const titleEl = document.createElement("div");
  titleEl.className = "chat-panel__title";
  titleEl.textContent = "Chat";
  /// Local-daemon health pill. Hidden during normal operation;
  /// surfaces a plain-English label whenever the chat backend can't
  /// sign or reach the relay, so the user never has to wonder why
  /// sends are stuck. Driven by the `chat:daemon-status` Tauri event
  /// (see src-tauri/src/chat.rs::spawn_daemon_watcher).
  const daemonPill = document.createElement("span");
  daemonPill.className = "chat-panel__daemon";
  daemonPill.setAttribute("role", "status");
  daemonPill.setAttribute("aria-live", "polite");
  daemonPill.hidden = true;

  const idBadge = document.createElement("button");
  idBadge.type = "button";
  idBadge.className = "chat-panel__id";
  idBadge.textContent = "—";
  idBadge.title = "Share your card";
  idBadge.setAttribute("aria-label", "Share your card");

  const shareBtn = document.createElement("button");
  shareBtn.type = "button";
  shareBtn.className = "chat-panel__share";
  shareBtn.textContent = "Share my card";

  // First-contact request badge — hidden until the store has at least
  // one pending TOFU welcome to surface. Clicking opens the dialog
  // that lets the user accept/reject the request.
  const pendingBtn = document.createElement("button");
  pendingBtn.type = "button";
  pendingBtn.className = "chat-panel__pending";
  pendingBtn.hidden = true;
  pendingBtn.setAttribute("aria-label", "Pending contact requests");
  pendingBtn.title = "Pending contact requests";

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

  headerEl.appendChild(litMark);
  headerEl.appendChild(titleEl);
  headerEl.appendChild(daemonPill);
  headerEl.appendChild(idBadge);
  headerEl.appendChild(shareBtn);
  headerEl.appendChild(pendingBtn);
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
  outboxRetry.addEventListener("click", () => {
    store.resetFailedRetryCounters();
    outboxDriver?.flushAll();
  });
  outboxBanner.appendChild(outboxLabel);
  outboxBanner.appendChild(outboxRetry);

  // Transient notice stack — fed by store.pushNotice. One row per
  // active notice; the staleness tick expires them after
  // TRANSIENT_NOTICE_MS. Each row has a manual dismiss button so a
  // user who clicks first wins over the auto-expire.
  const noticesEl = document.createElement("div");
  noticesEl.className = "chat-notices";
  noticesEl.setAttribute("role", "status");
  noticesEl.setAttribute("aria-live", "polite");

  const sidebarEl = document.createElement("aside");
  const conversationEl = document.createElement("section");
  // dialogHost is mounted on document.body and pre-styled with the
  // chat-dialog class from the start (just hidden). When a dialog
  // opens, only `hidden = false` + child insertion happens — no class
  // change, no late-applied position:absolute. webkit2gtk on Linux
  // wedges its compositor when a hidden element gets its positioning
  // class and its first children in the same task; pre-styling
  // sidesteps that path.
  const dialogHost = document.createElement("div");
  dialogHost.className = "chat-dialog";
  dialogHost.hidden = true;

  layout.appendChild(sidebarEl);
  layout.appendChild(conversationEl);

  host.appendChild(headerEl);
  host.appendChild(outboxBanner);
  host.appendChild(noticesEl);
  host.appendChild(layout);
  document.body.appendChild(dialogHost);

  let lastUnread = -1;
  store.subscribe(() => {
    const next = store.unreadCount();
    if (next === lastUnread) return;
    lastUnread = next;
    handlers.onUnreadChange?.(next);
  });

  const renderOutboxBanner = (): void => {
    const pending = store.pendingOutbound();
    if (pending.length === 0) {
      outboxBanner.hidden = true;
      return;
    }
    const failed = pending.filter((p) => p.bubble.status === "failed");
    const waiting = pending.length - failed.length;
    const parts: string[] = [];
    if (waiting > 0) parts.push(`${waiting} waiting to deliver`);
    if (failed.length > 0) parts.push(`${failed.length} undelivered`);
    outboxLabel.textContent = parts.join(" · ");
    // Retry only makes sense when something can plausibly be re-sent
    // right now — i.e. at least one failed bubble's peer is online.
    const retryable = failed.some(({ peer }) => store.isOnline(peer));
    outboxRetry.hidden = !retryable;
    outboxBanner.hidden = false;
  };
  store.subscribe(renderOutboxBanner);

  /// Repaint the status pill on every store-emit. Plain English copy
  /// on purpose — no "daemon", "x0xd" or "relay" jargon — so a
  /// non-technical user can read it without context. Daemon health
  /// wins over relay-link health: a down daemon means nothing works,
  /// so the relay label only shows once the local service is fine.
  const renderDaemonPill = (): void => {
    const daemon = store.getDaemonStatus();
    if (daemon && daemon !== "connected") {
      daemonPill.hidden = false;
      daemonPill.dataset.state = daemon;
      daemonPill.textContent =
        daemon === "reconnecting" ? "Reconnecting…" : "Chat service offline";
      return;
    }
    const relay = store.getRelayStatus();
    if (relay && relay !== "connected") {
      daemonPill.hidden = false;
      daemonPill.dataset.state = relay;
      daemonPill.textContent =
        relay === "connecting"
          ? "Connecting…"
          : relay === "reconnecting"
            ? "Reconnecting…"
            : "Chat offline";
      return;
    }
    daemonPill.hidden = true;
    daemonPill.textContent = "";
    daemonPill.dataset.state = daemon ?? "connected";
  };
  store.subscribe(renderDaemonPill);
  renderDaemonPill();

  const showDialog = (mount: (root: HTMLElement) => void): void => {
    dialogHost.hidden = false;
    mount(dialogHost);
  };
  const hideDialog = (): void => {
    dialogHost.hidden = true;
    dialogHost.replaceChildren();
  };

  const openShareCard = (): void => {
    showDialog((root) => {
      mountShareCard(root, { onClose: hideDialog });
    });
  };

  // Wire-up for both v2 (chat_import_card) and v3 (chat_pair_accept):
  // for v3, the result carries the imported peer's agent_id so we can
  // jump straight into the new DM, AND a crossRelay hint so we can
  // surface "you're on different relays" before the user wonders why
  // their first message disappears into the void.
  const handleImported = (
    result?: { agentIdHex: string; offererRelayUrl?: string; crossRelay?: boolean },
  ): void => {
    hideDialog();
    if (result?.agentIdHex) {
      store.setActive({ kind: "dm", peer: result.agentIdHex });
    }
    if (result?.crossRelay) {
      store.pushNotice(
        "warn",
        `This contact is on a different relay (${result.offererRelayUrl}). `
          + "Switch to the same one in Settings → Network or messages won't deliver.",
      );
    }
    void refreshContacts();
  };

  const openAddContact = (): void => {
    showDialog((root) => {
      mountAddContact(root, {
        onClose: hideDialog,
        onImported: handleImported,
      });
    });
  };

  const openPendingContacts = (): void => {
    showDialog((root) => {
      mountPendingContactsDialog(root, store, { onClose: hideDialog });
    });
  };

  const renderNotices = (): void => {
    const notices = store.allNotices();
    noticesEl.replaceChildren();
    for (const n of notices) {
      const row = document.createElement("div");
      row.className = `chat-notice chat-notice--${n.severity}`;
      row.dataset.id = n.id;
      const body = document.createElement("span");
      body.className = "chat-notice__body";
      body.textContent = n.body;
      const dismiss = document.createElement("button");
      dismiss.type = "button";
      dismiss.className = "chat-notice__dismiss";
      dismiss.setAttribute("aria-label", "Dismiss");
      dismiss.textContent = "✕";
      dismiss.addEventListener("click", () => store.dismissNotice(n.id));
      row.appendChild(body);
      row.appendChild(dismiss);
      noticesEl.appendChild(row);
    }
  };
  store.subscribe(renderNotices);
  renderNotices();

  const renderPendingBadge = (): void => {
    const n = store.allPendingContacts().length;
    pendingBtn.hidden = n === 0;
    pendingBtn.textContent = n > 0 ? `${n} new` : "";
    pendingBtn.title = n === 1
      ? "1 pending contact request"
      : `${n} pending contact requests`;
  };
  store.subscribe(renderPendingBadge);
  renderPendingBadge();
  pendingBtn.addEventListener("click", openPendingContacts);

  shareBtn.addEventListener("click", openShareCard);
  idBadge.addEventListener("click", () => {
    // In the bootstrap-failed state the badge doubles as a manual
    // "retry now" affordance — the title text is set in the catch
    // block. The share-card dialog is meaningless without an
    // identity, so route the click to open() instead of openShareCard.
    if (store.getDaemonStatus() === "down") {
      void open();
      return;
    }
    openShareCard();
  });

  const openNewGroup = (): void => {
    showDialog((root) => {
      mountNewGroup(root, resolveName(), {
        onClose: hideDialog,
        onCreated: () => {
          void refreshGroups();
        },
      });
    });
  };

  const openJoinGroup = (initialUri?: string): void => {
    showDialog((root) => {
      mountJoinGroup(
        root,
        resolveName(),
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

  const openPrefilledAddContact = (uri: string): void => {
    showDialog((root) => {
      mountAddContact(root, {
        onClose: hideDialog,
        onImported: handleImported,
      });
      const input = root.querySelector<HTMLTextAreaElement>(
        ".chat-dialog__uri",
      );
      if (input) {
        input.value = uri;
        input.dispatchEvent(new Event("input"));
      }
    });
  };

  const convHandle = mountConversation(conversationEl, store, {
    onAutonomi: (addr) => handlers.onAutonomi(addr),
    onCard: openPrefilledAddContact,
    onProfile: openPrefilledAddContact,
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
          unwatchPresence([agentId]).catch((e) =>
            console.warn("[chat] unwatchPresence:", e),
          );
          await refreshContacts();
        } catch (e) {
          console.warn("[chat] remove contact failed:", e);
        }
      })();
    },
    onLeaveGroup: (groupId) => {
      void (async () => {
        try {
          await leaveGroup(groupId);
          await refreshGroups();
          store.setActive(null);
        } catch (e) {
          console.warn("[chat] leave group failed:", e);
        }
      })();
    },
    resolveSenderName: resolveName,
  });

  const refreshContacts = async (): Promise<void> => {
    try {
      const contacts = await listContacts();
      store.loadContacts(contacts);
      const me = store.myId();
      const ids = contacts
        .filter((c) => c.agent_id !== me)
        .map((c) => c.agent_id);
      if (ids.length > 0) {
        watchPresence(ids).catch((e) =>
          console.warn("[chat] watchPresence on refresh:", e),
        );
      }
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
  let outboxDriver: OutboxDriver | null = null;
  /// Set when bootstrap (`open`) fails partway. Re-runs `open` after
  /// `BOOTSTRAP_RETRY_MS` so a daemon coming back online is picked
  /// up without forcing the user to re-toggle the panel.
  let bootstrapRetryTimer: ReturnType<typeof setTimeout> | null = null;
  /// Re-entrancy guard for `open()`. The retry timer + the idBadge
  /// click handler can both fire while a previous open is still
  /// awaiting `health()` / `identity()` — without this, two
  /// concurrent opens would both pass `eventsBound` guards and
  /// double-bind the chat listeners.
  let opening = false;
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
    if (opening) return;
    opening = true;
    host.hidden = false;
    applyDock();
    store.setPanelVisible(true);
    // Each attempt starts clean; a failure below re-renders the card.
    host.querySelector(".chat-unavailable")?.remove();
    try {
      await health();
      const [me, persistedName] = await Promise.all([
        identity(),
        getDisplayName().catch(() => ""),
      ]);
      displayName = persistedName;
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
      const watchIds = contacts
        .filter((c) => c.agent_id !== me.agent_id)
        .map((c) => c.agent_id);
      if (watchIds.length > 0) {
        watchPresence(watchIds).catch((e) =>
          console.warn("[chat] watchPresence on open:", e),
        );
      }
      if (!eventsBound) {
        eventsBound = true;
        await bindChatEvents(store);
      }
      if (!outboxDriver) {
        outboxDriver = startOutboxDriver(store, {
          sendDm: (peer, body) => sendDm(peer, body, resolveName()),
          connect: dmConnect,
        });
      }
      startStalenessTick();
      // Bootstrap succeeded — cancel any retry that the previous
      // attempt scheduled.
      if (bootstrapRetryTimer !== null) {
        clearTimeout(bootstrapRetryTimer);
        bootstrapRetryTimer = null;
      }
      opening = false;
    } catch (e) {
      idBadge.textContent = "Chat unavailable";
      idBadge.title = "Tap to retry";
      renderChatUnavailableCard(host, classifyBootstrapError(e));
      // Visible signal that something is wrong on top of the badge
      // text change. Drives the same pill the daemon-status watcher
      // uses so users get a consistent "something's wrong" cue.
      store.setDaemonStatus("down");
      console.warn("[chat] bootstrap failed:", e);
      // Schedule a retry — matches the x0xd supervisor's cadence so
      // a daemon coming back up is picked up within a few seconds.
      if (bootstrapRetryTimer === null) {
        bootstrapRetryTimer = setTimeout(() => {
          bootstrapRetryTimer = null;
          if (!host.hidden) void open();
        }, BOOTSTRAP_RETRY_MS);
      }
      opening = false;
    }
  };

  const close = (): void => {
    host.hidden = true;
    document.body.classList.remove("chat-docked");
    store.setPanelVisible(false);
    stopStalenessTick();
    if (bootstrapRetryTimer !== null) {
      clearTimeout(bootstrapRetryTimer);
      bootstrapRetryTimer = null;
    }
    // Stop the group-poll timer but keep the render subscription
    // alive — `mountConversation` is called once at panel construction
    // and the panel can be re-opened many times. Calling `dispose()`
    // here would unsubscribe the render listener permanently and
    // every subsequent open() would paint stale DOM.
    convHandle.stopPolling();
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
    async openDm(agentIdHex: string) {
      await open();
      // Same post-import jump handleImported performs: select the DM
      // and refresh so the new contact's row is present.
      store.setActive({ kind: "dm", peer: agentIdHex });
      void refreshContacts();
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
