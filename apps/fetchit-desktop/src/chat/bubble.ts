// Render a single chat-message bubble. Detects `autonomi://` and
// `x0x://` links in the body and turns them into clickable affordances
// — autonomi addresses open a new fetch>it tab; x0x cards / invites
// route to the appropriate chat dialog.

import type { ChatBubble } from "./state";
import { extractAutonomiAddresses, mountAutonomiPreview } from "./bubblePreview";

const URL_RE = /(autonomi:\/\/[0-9a-fA-F]{64}|x0x:\/\/(?:agent|invite)\/[A-Za-z0-9_-]+)/g;

export interface BubbleHandlers {
  onAutonomi: (addr: string) => void;
  onCard: (uri: string) => void;
  onInvite: (uri: string) => void;
}

export function renderBubble(
  b: ChatBubble,
  handlers: BubbleHandlers,
): HTMLElement {
  const row = document.createElement("div");
  row.className = `chat-row chat-row--${b.mine ? "out" : "in"}`;

  const stack = document.createElement("div");
  stack.className = "chat-bubble__stack";

  const bubble = document.createElement("div");
  bubble.className = "chat-bubble";
  if (b.mine && b.status && b.status !== "delivered") {
    bubble.dataset.status = b.status;
  }
  appendBodyWithLinks(bubble, b.body, handlers);
  if (b.mine && b.status && b.status !== "delivered") {
    bubble.appendChild(statusIcon(b.status, b.failureReason));
  }
  stack.appendChild(bubble);

  for (const addr of extractAutonomiAddresses(b.body)) {
    mountAutonomiPreview(stack, addr, { onOpen: handlers.onAutonomi });
  }

  const meta = document.createElement("time");
  meta.className = "chat-bubble__meta";
  meta.textContent = formatTime(b.timestampMs);
  meta.dateTime = new Date(b.timestampMs).toISOString();

  row.appendChild(stack);
  row.appendChild(meta);
  return row;
}

function appendBodyWithLinks(
  parent: HTMLElement,
  body: string,
  handlers: BubbleHandlers,
): void {
  let cursor = 0;
  for (const m of body.matchAll(URL_RE)) {
    const start = m.index ?? 0;
    if (start > cursor) {
      parent.appendChild(document.createTextNode(body.slice(cursor, start)));
    }
    const url = m[0];
    parent.appendChild(linkFor(url, handlers));
    cursor = start + url.length;
  }
  if (cursor < body.length) {
    parent.appendChild(document.createTextNode(body.slice(cursor)));
  }
}

function linkFor(url: string, h: BubbleHandlers): HTMLElement {
  const a = document.createElement("a");
  a.className = "chat-link";
  a.href = "#";
  a.textContent = compactUrl(url);
  a.title = url;
  a.addEventListener("click", (e) => {
    e.preventDefault();
    if (url.startsWith("autonomi://")) h.onAutonomi(url);
    else if (url.startsWith("x0x://invite/")) h.onInvite(url);
    else if (url.startsWith("x0x://agent/")) h.onCard(url);
  });
  return a;
}

function statusIcon(status: "pending" | "failed", reason?: string): HTMLElement {
  const span = document.createElement("span");
  span.className = `chat-bubble__status chat-bubble__status--${status}`;
  if (status === "pending") {
    span.textContent = "◌";
    span.title = "Sending…";
  } else {
    span.textContent = "⚠";
    span.title = reason ? `Not delivered: ${reason}` : "Not delivered";
  }
  return span;
}

function compactUrl(url: string): string {
  if (url.startsWith("autonomi://") && url.length > 16) {
    return `${url.slice(0, 19)}…${url.slice(-4)}`;
  }
  if (url.length > 28) return `${url.slice(0, 18)}…${url.slice(-6)}`;
  return url;
}

function formatTime(ms: number): string {
  if (!ms) return "";
  const d = new Date(ms);
  const now = new Date();
  const sameDay =
    d.getFullYear() === now.getFullYear()
    && d.getMonth() === now.getMonth()
    && d.getDate() === now.getDate();
  if (sameDay) {
    return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  }
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}
