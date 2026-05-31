// The right-pane conversation view: header (peer / group title +
// presence + actions), scrollable message stream, composer.

import { bubbleRenderKey, renderBubble, type BubbleHandlers } from "./bubble";
import { mountComposer } from "./composer";
import { chatConfirm } from "./confirmDialog";
import { convKey, type ChatStore, type Conversation } from "./state";
import { dmConnect, groupHistory, sendDm, sendGroupMessage } from "./api";
import { friendlyError } from "./errors";
import { mountTrustMenu } from "./trustMenu";
import type { TrustLevel } from "./types";

const GROUP_POLL_INTERVAL_MS = 4_000;

export interface ConversationHandlers {
  onAutonomi: (addr: string) => void;
  onCard: (uri: string) => void;
  onInvite: (uri: string) => void;
  onProfile: (uri: string) => void;
  onAddContact: () => void;
  onSetTrust: (agentId: string, level: TrustLevel) => void;
  onRemoveContact: (agentId: string) => void;
  onLeaveGroup: (groupId: string) => void;
  /// Resolves the user's current display name at send time, so a rename
  /// in the share-card dialog takes effect on the next outbound DM
  /// without re-mounting.
  resolveSenderName: () => string;
}

export function mountConversation(
  root: HTMLElement,
  store: ChatStore,
  handlers: ConversationHandlers,
): { dispose: () => void } {
  root.replaceChildren();
  root.className = "chat-conversation";

  const headerEl = document.createElement("header");
  headerEl.className = "chat-conv-header";
  const subjectEl = document.createElement("div");
  subjectEl.className = "chat-conv-header__subject";
  const presenceEl = document.createElement("span");
  presenceEl.className = "chat-conv-header__presence";
  const trustEl = document.createElement("div");
  trustEl.hidden = true;
  headerEl.appendChild(subjectEl);
  headerEl.appendChild(presenceEl);
  headerEl.appendChild(trustEl);

  const stream = document.createElement("div");
  stream.className = "chat-stream";
  stream.setAttribute("aria-live", "polite");

  const composerEl = document.createElement("div");

  root.appendChild(headerEl);
  root.appendChild(stream);
  root.appendChild(composerEl);

  const bubbleHandlers: BubbleHandlers = {
    onAutonomi: handlers.onAutonomi,
    onCard: handlers.onCard,
    onInvite: handlers.onInvite,
    onProfile: handlers.onProfile,
  };

  let lastConv: Conversation | null = null;
  /// Signature of the most recent bubble list we rendered, used to
  /// short-circuit store-subscribe ticks that don't change anything in
  /// the message column. Without this guard, `replaceChildren` detaches
  /// + re-attaches every bubble even when the keyed-diff reuses the
  /// same DOM nodes, which restarts the `chat-bubble-pop` animation
  /// and produces visible flicker on every presence / nearby tick.
  let lastStreamKey: string | null = null;
  let groupPollTimer: ReturnType<typeof setInterval> | null = null;

  const refreshGroupHistory = (groupId: string): Promise<void> =>
    groupHistory(groupId)
      .then((msgs) => store.recordGroupHistory(groupId, msgs))
      .catch((e) => console.warn("[chat] group history fetch:", e));

  const stopGroupPoll = (): void => {
    if (groupPollTimer !== null) {
      clearInterval(groupPollTimer);
      groupPollTimer = null;
    }
  };

  const composer = mountComposer(composerEl, {
    onSend: (body) => {
      const conv = store.active();
      if (!conv) return;
      if (conv.key.kind === "dm") {
        const peer = conv.key.peer;
        const bubbleId = store.enqueueOutbound(peer, body);
        void (async () => {
          try {
            // Same warmup the driver does for retries — turns a 12s
            // cold-link timeout into a sub-second raw_quic send.
            await dmConnect(peer).catch(() => {});
            const messageId = await sendDm(peer, body, handlers.resolveSenderName());
            store.markSent(peer, bubbleId, messageId);
          } catch (e) {
            store.markFailed(peer, bubbleId, (e as Error).message);
          }
        })();
      } else {
        const groupId = conv.key.groupId;
        // Fire the send, then refresh history so the user sees their
        // own bubble appear without waiting for the next poll tick.
        void sendGroupMessage(groupId, body)
          .then(() => refreshGroupHistory(groupId))
          .catch((e) => {
            console.warn("[chat] group send failed:", e);
            // Surface to the user — silent group-send failure was an
            // audit-flagged grandma-trap. The notice replaces the
            // old console-only log.
            store.pushNotice(
              "warn",
              `Couldn't send to group: ${friendlyError(e)}`,
            );
          });
      }
    },
  });

  const render = (): void => {
    const conv = store.active();
    if (!conv) {
      subjectEl.textContent = "";
      presenceEl.textContent = "";
      trustEl.hidden = true;
      trustEl.replaceChildren();
      stream.replaceChildren(emptyPane(handlers.onAddContact));
      composer.setEnabled(false, "Select a conversation to start writing…");
      return;
    }
    composer.setEnabled(true);

    subjectEl.textContent = conv.title;
    if (conv.key.kind === "dm") {
      const peer = conv.key.peer;
      const online = store.isOnline(peer);
      presenceEl.textContent = online ? "online" : "offline";
      presenceEl.dataset.state = online ? "online" : "offline";
      const contact = store.contact(peer);
      if (contact) {
        trustEl.hidden = false;
        mountTrustMenu(trustEl, contact, {
          onSetTrust: (level) => handlers.onSetTrust(peer, level),
          onRemove: () => handlers.onRemoveContact(peer),
        });
      } else {
        trustEl.hidden = true;
        trustEl.replaceChildren();
      }
    } else {
      presenceEl.textContent = "group";
      presenceEl.dataset.state = "group";
      const groupId = conv.key.groupId;
      trustEl.hidden = false;
      trustEl.replaceChildren();
      trustEl.className = "chat-group-actions";
      const leaveBtn = document.createElement("button");
      leaveBtn.type = "button";
      leaveBtn.className = "chat-trust__remove";
      leaveBtn.textContent = "Leave";
      leaveBtn.title = "Leave / delete this group";
      leaveBtn.addEventListener("click", () => {
        const title = conv.title;
        void (async () => {
          const ok = await chatConfirm({
            title: "Leave group",
            message: `Leave "${title}"? You'll need a new invite to rejoin.`,
            confirmLabel: "Leave",
          });
          if (ok) handlers.onLeaveGroup(groupId);
        })();
      });
      trustEl.appendChild(leaveBtn);
    }

    // Bubble list signature: conv identity + ordered bubble keys. When
    // it matches the previous render, the DOM doesn't need to move at
    // all. `replaceChildren` would re-attach every bubble and re-fire
    // chat-bubble-pop even on a keyed-reuse, so we have to short-circuit
    // *before* touching `stream`.
    const newStreamKey = `${convKey(conv.key)}|${conv.messages.map(bubbleRenderKey).join("|")}`;
    if (newStreamKey !== lastStreamKey || lastConv !== conv) {
      const wasAtBottom = isNearBottom(stream);
      // Keyed diff: reuse existing bubble elements whose render key
      // (id + status + failureReason) is unchanged. New bubbles get
      // built; orphans (removed messages) drop on the floor.
      const existing = new Map<string, HTMLElement>();
      for (const child of Array.from(stream.children)) {
        const key = (child as HTMLElement).dataset.key;
        if (key) existing.set(key, child as HTMLElement);
      }
      const ordered: HTMLElement[] = [];
      for (const b of conv.messages) {
        const key = bubbleRenderKey(b);
        const reused = existing.get(key);
        if (reused) {
          existing.delete(key);
          ordered.push(reused);
        } else {
          ordered.push(renderBubble(b, bubbleHandlers));
        }
      }
      stream.replaceChildren(...ordered);
      lastStreamKey = newStreamKey;
      if (lastConv !== conv || wasAtBottom) {
        stream.scrollTop = stream.scrollHeight;
      }
    }
    if (lastConv !== conv) {
      composer.focus();
      // Entering a DM is a cheap chance to probe reachability — if the
      // QUIC handshake succeeds, treat the peer as freshly online even
      // when their gossip beacon to the daemon is lagging.
      if (conv.key.kind === "dm") {
        stopGroupPoll();
        const peer = conv.key.peer;
        // Best-effort warmup so the first send doesn't pay the cold-link
        // latency. The relay's PresenceUpdate stream — not this probe —
        // owns the online dot.
        void dmConnect(peer).catch(() => {});
      } else {
        // Group: there's no group-message SSE wired through yet, so
        // poll `/groups/<id>/messages` while this conv is active. One
        // immediate refresh, then on a small interval.
        const groupId = conv.key.groupId;
        stopGroupPoll();
        void refreshGroupHistory(groupId);
        groupPollTimer = setInterval(() => {
          if (store.active()?.key.kind !== "group") {
            stopGroupPoll();
            return;
          }
          void refreshGroupHistory(groupId);
        }, GROUP_POLL_INTERVAL_MS);
      }
    }
    lastConv = conv;
  };

  const unsub = store.subscribe(render);
  render();
  return {
    dispose: () => {
      stopGroupPoll();
      unsub();
    },
  };
}

function isNearBottom(el: HTMLElement): boolean {
  return el.scrollHeight - el.scrollTop - el.clientHeight < 48;
}

function emptyPane(onAddContact: () => void): HTMLElement {
  const wrap = document.createElement("div");
  wrap.className = "chat-empty";
  const title = document.createElement("div");
  title.className = "chat-empty__title";
  title.textContent = "Pick a conversation";
  const body = document.createElement("div");
  body.className = "chat-empty__body";
  body.textContent = "Choose a contact on the left, or add a new one.";
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "chat-empty__cta";
  btn.textContent = "Add a contact";
  btn.addEventListener("click", onAddContact);
  wrap.appendChild(title);
  wrap.appendChild(body);
  wrap.appendChild(btn);
  return wrap;
}
