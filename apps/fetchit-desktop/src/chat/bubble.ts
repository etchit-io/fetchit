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

  const addresses = extractAutonomiAddresses(b.body);

  const bubble = document.createElement("div");
  bubble.className = "chat-bubble";
  const showStatus = b.mine && !!b.status;
  if (showStatus) {
    bubble.dataset.status = b.status;
  }
  const hasSurroundingText = appendBodyWithLinks(
    bubble,
    b.body,
    handlers,
    /* skipAutonomi */ addresses.length > 0,
  );
  if (showStatus) {
    bubble.appendChild(statusIcon(b.status as BubbleStatusTag, b.failureReason));
  }
  // Suppress the text bubble entirely when the only content was
  // autonomi:// links — the preview card below already represents
  // the address. Keep it around when there's surrounding text, or
  // when we still need to show a sending / failed status indicator.
  if (hasSurroundingText || addresses.length === 0 || showStatus) {
    stack.appendChild(bubble);
  }

  for (const addr of addresses) {
    mountAutonomiPreview(stack, addr, { onOpen: handlers.onAutonomi });
  }

  if (showStatus && b.status !== "delivered") {
    stack.appendChild(substatusCaption(b.status as BubbleStatusTag, b.failureReason));
  }

  const meta = document.createElement("time");
  meta.className = "chat-bubble__meta";
  meta.textContent = formatTime(b.timestampMs);
  meta.dateTime = new Date(b.timestampMs).toISOString();

  row.appendChild(stack);
  row.appendChild(meta);
  return row;
}

/// Returns true if any non-whitespace text or non-autonomi link was
/// emitted into `parent`. When `skipAutonomi` is set, autonomi:// URLs
/// are dropped from the rendered text since the preview card below
/// already represents them.
function appendBodyWithLinks(
  parent: HTMLElement,
  body: string,
  handlers: BubbleHandlers,
  skipAutonomi = false,
): boolean {
  let cursor = 0;
  let hasContent = false;
  for (const m of body.matchAll(URL_RE)) {
    const start = m.index ?? 0;
    if (start > cursor) {
      const slice = body.slice(cursor, start);
      parent.appendChild(document.createTextNode(slice));
      if (slice.trim().length > 0) hasContent = true;
    }
    const url = m[0];
    if (skipAutonomi && url.startsWith("autonomi://")) {
      // dropped — preview card represents it
    } else {
      parent.appendChild(linkFor(url, handlers));
      hasContent = true;
    }
    cursor = start + url.length;
  }
  if (cursor < body.length) {
    const slice = body.slice(cursor);
    parent.appendChild(document.createTextNode(slice));
    if (slice.trim().length > 0) hasContent = true;
  }
  return hasContent;
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

type BubbleStatusTag = "sending" | "delivered" | "failed";

function substatusCaption(
  status: BubbleStatusTag,
  reason?: string,
): HTMLElement {
  const cap = document.createElement("div");
  cap.className = `chat-bubble__substatus chat-bubble__substatus--${status}`;
  if (status === "sending") {
    cap.textContent = "Sending…";
  } else if (status === "failed") {
    cap.textContent = "Not delivered";
    if (reason) cap.title = reason;
  }
  return cap;
}

function statusIcon(
  status: BubbleStatusTag,
  reason?: string,
): HTMLElement {
  const span = document.createElement("span");
  span.className = `chat-bubble__status chat-bubble__status--${status}`;
  switch (status) {
    case "sending":
      span.textContent = "⏳";
      span.title = "Sending…";
      break;
    case "delivered":
      span.textContent = "✓";
      span.title = "Delivered";
      break;
    case "failed":
      span.textContent = "⚠";
      span.title = reason ? `Not delivered: ${reason}` : "Not delivered";
      break;
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
