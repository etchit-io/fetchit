// The right-pane conversation view: header (peer / group title +
// presence + actions), scrollable message stream, composer.

import { renderBubble, type BubbleHandlers } from "./bubble";
import { mountComposer } from "./composer";
import type { ChatStore, Conversation } from "./state";
import { sendDm, sendGroupMessage } from "./api";
import { mountTrustMenu } from "./trustMenu";
import type { TrustLevel } from "./types";

export interface ConversationHandlers {
  onAutonomi: (addr: string) => void;
  onCard: (uri: string) => void;
  onInvite: (uri: string) => void;
  onAddContact: () => void;
  onSetTrust: (agentId: string, level: TrustLevel) => void;
  onRemoveContact: (agentId: string) => void;
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
  };

  let lastConv: Conversation | null = null;
  const composer = mountComposer(composerEl, {
    onSend: (body) => {
      const conv = store.active();
      if (!conv) return;
      if (conv.key.kind === "dm") {
        const peer = conv.key.peer;
        const bubbleId = store.enqueueOutbound(peer, body);
        void sendDm(peer, body).then(
          () => store.markDelivered(peer, bubbleId),
          (e: unknown) =>
            store.markFailed(peer, bubbleId, (e as Error).message),
        );
      } else {
        void sendGroupMessage(conv.key.groupId, body).catch((e) =>
          console.warn("[chat] group send failed:", e),
        );
      }
    },
  });

  const render = (): void => {
    const conv = store.active();
    if (!conv) {
      subjectEl.textContent = "";
      presenceEl.textContent = "";
      stream.replaceChildren(emptyPane(handlers.onAddContact));
      composerEl.hidden = true;
      return;
    }
    composerEl.hidden = false;

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
      trustEl.hidden = true;
      trustEl.replaceChildren();
    }

    const wasAtBottom = isNearBottom(stream);
    stream.replaceChildren();
    for (const b of conv.messages) {
      stream.appendChild(renderBubble(b, bubbleHandlers));
    }
    if (lastConv !== conv || wasAtBottom) {
      stream.scrollTop = stream.scrollHeight;
    }
    if (lastConv !== conv) {
      composer.focus();
    }
    lastConv = conv;
  };

  const unsub = store.subscribe(render);
  render();
  return {
    dispose: () => {
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
