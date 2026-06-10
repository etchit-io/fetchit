// Render a single chat-message bubble. Detects `autonomi://`, `x0x://`,
// and `fetchit://share/v3/` links in the body and turns them into
// clickable affordances — autonomi addresses open a new fetch>it tab;
// x0x cards / invites and v3 share URIs route to the appropriate
// chat dialog.

import type { ChatBubble, QuotedRef } from "./state";
import { extractAutonomiAddresses, mountAutonomiPreview } from "./bubblePreview";
import { appendInlineMarkdown } from "./markdown";

const URL_RE
  = /(autonomi:\/\/[0-9a-fA-F]{64}|x0x:\/\/(?:agent|invite)\/[A-Za-z0-9_-]+|fetchit:\/\/share\/v3\/[0-9a-fA-F]{64}\/[0-9a-fA-F]{64}\?relay=\S+)/g;

export interface BubbleHandlers {
  onAutonomi: (addr: string) => void;
  onCard: (uri: string) => void;
  onInvite: (uri: string) => void;
  /// v3 share URI — routes through the same add-contact dialog as
  /// `onCard` but the dialog will dispatch the import to the v3
  /// pair-accept command instead of the legacy import path.
  onProfile: (uri: string) => void;
}

/// A signature that uniquely identifies the rendered shape of a
/// bubble. Two bubbles with the same key render to identical DOM
/// (modulo time formatting), so the conversation pane can reuse the
/// existing element instead of recreating it — which is what keeps
/// the `chat-bubble-pop` enter animation from re-firing on every
/// store mutation.
export function bubbleRenderKey(b: ChatBubble): string {
  return `${b.id}|${b.status ?? ""}|${b.failureReason ?? ""}|${b.verified ?? ""}|${b.replyTo?.messageId ?? ""}`;
}

export function renderBubble(
  b: ChatBubble,
  handlers: BubbleHandlers,
): HTMLElement {
  const row = document.createElement("div");
  row.className = `chat-row chat-row--${b.mine ? "out" : "in"}`;
  row.dataset.key = bubbleRenderKey(b);

  const stack = document.createElement("div");
  stack.className = "chat-bubble__stack";

  // Quoted parent renders above the body, independent of whether the
  // body itself collapses to an autonomi preview card.
  if (b.replyTo) {
    stack.appendChild(renderQuote(b.replyTo));
  }

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

  // Unverified-sender badge — inbound messages whose per-message
  // signature couldn't be cryptographically verified by THIS process.
  // The M0 honesty floor: surface it instead of synthesizing
  // verified=true. Outbound bubbles never carry this since
  // verification doesn't apply to messages we sent.
  if (!b.mine && b.verified === false) {
    stack.appendChild(unverifiedSenderBadge());
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
      appendInlineMarkdown(parent, slice);
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
    appendInlineMarkdown(parent, slice);
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
    else if (url.startsWith("fetchit://share/v3/")) h.onProfile(url);
  });
  return a;
}

/// Inline "unverified sender" tag rendered under a bubble whose
/// per-message signature couldn't be cryptographically checked against
/// a cached card pubkey. Pinned to the M0 honesty floor: better an
/// honest amber "we can't prove this is from them" than a synthesized
/// "verified" badge that lies.
function unverifiedSenderBadge(): HTMLElement {
  const span = document.createElement("div");
  span.className = "chat-bubble__unverified";
  span.textContent = "⚠ unverified sender";
  span.title
    = "We can't cryptographically verify this message came from the named sender."
    + " It may be from someone we don't have a contact card for, or from a transport"
    + " that doesn't carry per-message signatures.";
  return span;
}

/// Render the quoted-parent strip shown above a reply's body. Text-only
/// (sender + a short preview); no link parsing, since the preview is a
/// plain excerpt of the original.
function renderQuote(ref: QuotedRef): HTMLElement {
  const quote = document.createElement("div");
  quote.className = "chat-quote";
  const who = document.createElement("span");
  who.className = "chat-quote__sender";
  who.textContent = ref.senderName;
  const preview = document.createElement("span");
  preview.className = "chat-quote__preview";
  preview.textContent = ref.preview;
  quote.append(who, preview);
  return quote;
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
