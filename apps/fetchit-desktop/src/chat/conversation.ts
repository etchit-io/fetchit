// The right-pane conversation view: header (peer / group title +
// presence + actions), scrollable message stream, composer.

import { renderBubble, type BubbleHandlers } from "./bubble";
import { mountComposer } from "./composer";
import type { ChatStore, Conversation } from "./state";
import { sendDm, sendGroupMessage } from "./api";

export interface ConversationHandlers {
  onAutonomi: (addr: string) => void;
  onCard: (uri: string) => void;
  onInvite: (uri: string) => void;
  onAddContact: () => void;
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
  headerEl.appendChild(subjectEl);
  headerEl.appendChild(presenceEl);

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
    onSend: async (body) => {
      const conv = store.active();
      if (!conv) return;
      if (conv.key.kind === "dm") {
        await sendDm(conv.key.peer, body);
        store.recordDirectMessage({
          from: store.myId() ?? "",
          to: conv.key.peer,
          body,
          timestamp_ms: Date.now(),
          message_id: null,
        });
      } else {
        await sendGroupMessage(conv.key.groupId, body);
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
      const online = store.isOnline(conv.key.peer);
      presenceEl.textContent = online ? "online" : "offline";
      presenceEl.dataset.state = online ? "online" : "offline";
    } else {
      presenceEl.textContent = "group";
      presenceEl.dataset.state = "group";
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
