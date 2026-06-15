// The right-pane conversation view: header (peer / group title +
// presence + actions), scrollable message stream, composer.

import { bubbleRenderKey, renderBubble, type BubbleHandlers } from "./bubble";
import { mountComposer } from "./composer";
import { chatConfirm } from "./confirmDialog";
import { openImageLightbox } from "./lightbox";
import { convKey, quotedRef, type ChatStore, type Conversation } from "./state";
import {
  dmConnect,
  fetchAvatar,
  fetchProfile,
  groupHistory,
  sendDm,
  sendGroupMessage,
} from "./api";
import { friendlyError } from "./errors";
import { openProfileCard } from "./profileCard";
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
  /// Navigate to the full profile page for the given agent (caller closes chat).
  onOpenFullProfile: (agentId: string) => void;
  /// Resolves the user's current display name at send time, so a rename
  /// in the share-card dialog takes effect on the next outbound DM
  /// without re-mounting.
  resolveSenderName: () => string;
}

/// Handle returned by [`mountConversation`]. Lifecycle is two-tier:
///
/// * `stopPolling` halts the group-message poll timer only. Safe to
///   call when the chat panel hides — the render subscription stays
///   alive so a later panel-show resumes against fresh store state
///   without re-mounting the pane.
/// * `dispose` is the full teardown: stops the poll AND unsubscribes
///   from the store. Use only when the host element itself goes away;
///   panel-show/hide must not call this, or the next show will paint
///   stale DOM that never re-renders.
export interface ConversationHandle {
  stopPolling: () => void;
  dispose: () => void;
}

export function mountConversation(
  root: HTMLElement,
  store: ChatStore,
  handlers: ConversationHandlers,
): ConversationHandle {
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

  /// Quote-strip click: resolve the quoted id against local history
  /// (sender-side parents carry it as messageId, inbound parents as
  /// their bubble id), scroll the parent's row into view, and flash it.
  /// A trimmed-away parent is a silent no-op — the strip already says
  /// "(message unavailable)" in that case.
  const scrollToMessage = (messageId: string): void => {
    const conv = store.active();
    if (!conv) return;
    const parent = conv.messages.find(
      (m) => m.messageId === messageId || m.id === messageId,
    );
    if (!parent) return;
    const keyPrefix = `${parent.id}|`;
    for (const child of Array.from(stream.children)) {
      const el = child as HTMLElement;
      if (el.dataset.key?.startsWith(keyPrefix)) {
        el.scrollIntoView({ behavior: "smooth", block: "center" });
        el.classList.remove("chat-row--flash");
        // Force a reflow so re-adding the class restarts the animation
        // even when the same parent is jumped to twice in a row.
        void el.offsetWidth;
        el.classList.add("chat-row--flash");
        break;
      }
    }
  };

  // DM header subject opens the contact's read-only profile card. The
  // reader hand-off reuses the existing `onAutonomi`. fetch>it has no
  // external-browser capability, so a website link copies to the
  // clipboard behind a confirm rather than pretending to open. `onMessage`
  // is a no-op because the user is already in this DM.
  const viewProfile = (agentId: string): void => {
    openProfileCard({
      agentId,
      fetchProfile,
      fetchAvatar,
      onAutonomi: handlers.onAutonomi,
      onMessage: () => {},
      confirmOpen: (url) => {
        void chatConfirm({
          title: "Copy website link",
          message:
            "fetch>it doesn't open external sites, so this copies the link to "
            + "your clipboard:\n" + url,
          confirmLabel: "Copy link",
        }).then((ok) => {
          if (ok) void navigator.clipboard.writeText(url).catch(() => {});
        });
      },
      onOpenFullProfile: handlers.onOpenFullProfile,
    });
  };

  const bubbleHandlers: BubbleHandlers = {
    onAutonomi: handlers.onAutonomi,
    onCard: handlers.onCard,
    onInvite: handlers.onInvite,
    onProfile: handlers.onProfile,
    onQuoteClick: scrollToMessage,
    onImageOpen: openImageLightbox,
  };
  // DM bubbles get the reply affordance; group bubbles stay without it
  // until the payload carries the quote cross-peer — a reply affordance
  // whose quote silently vanishes on the recipients would be a broken
  // promise.
  const dmBubbleHandlers: BubbleHandlers = {
    ...bubbleHandlers,
    onReply: (b) => {
      const conv = store.active();
      if (!conv || conv.key.kind !== "dm") return;
      const senderName = b.mine ? handlers.resolveSenderName() : conv.title;
      composer.setReplyTo(quotedRef(b, senderName));
    },
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
  /// New messages that landed while the panel was hidden need a
  /// scroll-to-bottom on reopen — `isNearBottom` reads scrollHeight /
  /// scrollTop / clientHeight, all of which return 0 on a hidden
  /// subtree, so the in-place anchor write would land at scrollTop=0
  /// (off-screen). Defer the scroll anchor to the next visible render.
  ///
  /// Scoped to a specific conversation key so a hidden-time pivot
  /// (A → B → A) doesn't cause B's deferred-anchor flag to fire a
  /// scroll-to-bottom on A's reopen when A's content was unchanged.
  /// Null means no pending anchor for any conv.
  let pendingScrollForKey: string | null = null;

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
    onAttachError: (msg) => store.pushNotice("warn", msg),
    onSend: (body, replyTo, attachment) => {
      const conv = store.active();
      if (!conv) return;
      if (conv.key.kind === "dm") {
        const peer = conv.key.peer;
        // Stage shell-only render metadata (the engine OutboxBubble can't
        // carry the reply quote or attachment); stage once per send so the
        // per-peer FIFO stays aligned with the optimistic-echo order.
        const metaToken = store.stageOutboundMeta(peer, {
          replyTo: replyTo ?? undefined,
          attachment: attachment ?? undefined,
        });
        // enqueue_dm owns the bubble lifecycle end to end: optimistic echo
        // (rendered via the chat:outbox projection), warm-connect, send,
        // outcome recording, retry, and delivery. A rejection here means the
        // send never reached the engine (e.g. the local daemon is down), so
        // no bubble is ever echoed: drop the staged metadata we reserved or
        // it would mis-attach to the next send, then surface the error.
        void sendDm(
          peer,
          body,
          handlers.resolveSenderName(),
          replyTo?.messageId,
          attachment,
        ).catch((e) => {
          store.discardStagedMeta(peer, metaToken);
          store.pushNotice("warn", `Couldn't send: ${friendlyError(e)}`);
        });
      } else {
        const groupId = conv.key.groupId;
        // Fire the send, then refresh history so the user sees their
        // own bubble appear without waiting for the next poll tick.
        void sendGroupMessage(groupId, body, handlers.resolveSenderName())
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
    // M3 G2: refuse outbound to a denylisted DM peer. Group conversations
    // aren't agent-addressed so the gate is DM-only; the composer stays
    // open for groups regardless. Dormant until the denylist consumer is
    // energized — `isDenylisted` is always false with an empty set, so
    // the composer behaves exactly as before for every contact.
    if (conv.key.kind === "dm" && store.isDenylisted(conv.key.peer)) {
      composer.setEnabled(
        false,
        "This contact is on the community safety denylist — messages can't be sent.",
      );
    } else {
      composer.setEnabled(true);
    }
    // Inline images ride the DM payload only; groups carry no attachment
    // field yet, so hide the affordance there rather than promise a send
    // the wire would silently drop.
    composer.setAttachVisible(conv.key.kind === "dm");

    if (conv.key.kind === "dm") {
      const peer = conv.key.peer;
      const subjectBtn = document.createElement("button");
      subjectBtn.type = "button";
      subjectBtn.className = "chat-conv__subject-btn";
      subjectBtn.title = "View profile";
      subjectBtn.textContent = conv.title;
      subjectBtn.addEventListener("click", () => viewProfile(peer));
      subjectEl.replaceChildren(subjectBtn);
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
      subjectEl.textContent = conv.title;
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

    // Panel visibility gates the DOM diff + scroll anchor: while the
    // host is hidden, `stream.scrollHeight / scrollTop / clientHeight`
    // all report 0 and `isNearBottom` returns a spurious "yes", so any
    // scroll-anchor write lands at 0 (the top of the rebuilt stream).
    // We also drive the group-history poll off the same flag so
    // re-opening the panel after a close picks the poll back up even
    // when the same group is still active.
    const panelVisible = store.isPanelVisible();
    const newStreamKey = `${convKey(conv.key)}|${conv.messages.map(bubbleRenderKey).join("|")}`;

    if (!panelVisible) {
      // Defer scroll-to-bottom until we're visible again. Don't touch
      // `lastConv` from here — if the user pivots to a different conv
      // while the panel is hidden, the visible branch's `lastConv !==
      // conv` gate must still fire on reopen so focus + DM warmup +
      // group-poll lifecycle run for the conv the user returns to.
      //
      // Tag the deferred anchor with the current conv key so a later
      // hidden-time pivot doesn't carry a flag set for a different
      // conv through to reopen.
      if (newStreamKey !== lastStreamKey) {
        pendingScrollForKey = convKey(conv.key);
      }
      // The group-poll timer has no purpose while hidden — no UI to
      // refresh, no one to observe stale beacons. setPanelVisible(false)
      // is the canonical "go quiet" signal.
      stopGroupPoll();
      return;
    }

    // Bubble list signature: conv identity + ordered bubble keys. When
    // it matches the previous render, the DOM doesn't need to move at
    // all. `replaceChildren` would re-attach every bubble and re-fire
    // chat-bubble-pop even on a keyed-reuse, so we have to short-circuit
    // *before* touching `stream`. The visibility flip alone is NOT a
    // reason to re-diff — only an actual content change is. The deferred
    // scroll anchor below handles the show-after-new-content case
    // without re-detaching DOM nodes.
    // Note: there is no `else if (justBecameVisible && pending…)`
    // branch. By construction the hidden branch only sets
    // `pendingScrollForKey` when `newStreamKey !== lastStreamKey`,
    // so the same content-change condition that set the flag also
    // fires the diff branch below on the next visible render —
    // which clears the flag. The flag can only outlive a visible
    // render when it was set for a conv DIFFERENT from the active
    // one (hidden-time pivot to B → back to A with no A content
    // change). In that case the next render that DOES affect conv-B
    // (an explicit `setActive(B)` or B-side content) hits the diff
    // branch and the stale flag is cleared there. So a content-
    // unchanged visible render legitimately leaves the user's
    // scroll position alone.
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
      const activeBubbleHandlers =
        conv.key.kind === "dm" ? dmBubbleHandlers : bubbleHandlers;
      const ordered: HTMLElement[] = [];
      for (const b of conv.messages) {
        const key = bubbleRenderKey(b);
        const reused = existing.get(key);
        if (reused) {
          existing.delete(key);
          ordered.push(reused);
        } else {
          ordered.push(renderBubble(b, activeBubbleHandlers));
        }
      }
      stream.replaceChildren(...ordered);
      lastStreamKey = newStreamKey;
      const pendingForThisConv = pendingScrollForKey === convKey(conv.key);
      if (lastConv !== conv || wasAtBottom || pendingForThisConv) {
        stream.scrollTop = stream.scrollHeight;
      }
      // Clear regardless once the diff fired — any pending anchor
      // for this conv is satisfied; any pending anchor for a
      // different conv is stale.
      pendingScrollForKey = null;
    }
    if (lastConv !== conv) {
      composer.focus();
      // A reply or staged image pending against the previous
      // conversation must never attach to a message sent in this one.
      composer.setReplyTo(null);
      composer.clearAttachment();
      // Conv changed — tear down whatever conv-specific machinery was
      // running so we can start fresh below. Group→group switch was
      // previously buggy: the line below was inside a DM-only branch,
      // so a group A → group B selection left the closure polling A.
      stopGroupPoll();
      if (conv.key.kind === "dm") {
        const peer = conv.key.peer;
        // Best-effort warmup so the first send doesn't pay the cold-link
        // latency. The relay's PresenceUpdate stream — not this probe —
        // owns the online dot.
        void dmConnect(peer).catch(() => {});
      }
    }
    // Group-poll lifecycle is driven on every visible render that
    // finds an active group conv with no timer, not just on the
    // conv-changed transition. That way the timer comes back on the
    // panel-show after a close — staying on the same group across
    // close/reopen would otherwise leave the right pane stale. Also
    // covers the group→group switch above, where stopGroupPoll() just
    // cleared the timer.
    if (conv.key.kind === "group" && groupPollTimer === null) {
      const groupId = conv.key.groupId;
      void refreshGroupHistory(groupId);
      groupPollTimer = setInterval(() => {
        if (store.active()?.key.kind !== "group") {
          stopGroupPoll();
          return;
        }
        void refreshGroupHistory(groupId);
      }, GROUP_POLL_INTERVAL_MS);
    }
    lastConv = conv;
  };

  const unsub = store.subscribe(render);
  render();
  return {
    stopPolling: () => {
      stopGroupPoll();
    },
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
