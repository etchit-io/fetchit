// Render a single chat-message bubble. Detects `autonomi://`, `x0x://`,
// and `fetchit://share/v3/` links in the body and turns them into
// clickable affordances — autonomi addresses open a new fetch>it tab;
// x0x cards / invites and v3 share URIs route to the appropriate
// chat dialog.

import type { ChatBubble, QuotedRef } from "./state";
import type { Attachment } from "./types";
import { bubbleIdentityClass, senderIdentityClass } from "./avatarColor";
import { extractAutonomiAddresses, mountAutonomiPreview } from "./bubblePreview";
import { appendInlineMarkdown } from "./markdown";
import { attachmentDataUrl } from "./imageAttach";

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
  /// Present only when the conversation supports replying (DMs for
  /// now — group quotes need the wire field). When set, each bubble
  /// renders a hover reply affordance that fires with the bubble.
  onReply?: (b: ChatBubble) => void;
  /// Fired when the user clicks a quoted-parent strip; receives the
  /// quoted message id so the conversation can scroll to the parent.
  onQuoteClick?: (messageId: string) => void;
  /// Fired when the user clicks an inline-image thumbnail; receives the
  /// attachment so the conversation can open it full-size.
  onImageOpen?: (att: Attachment) => void;
}

/// A signature that uniquely identifies the rendered shape of a
/// bubble. Two bubbles with the same key render to identical DOM
/// (modulo time formatting), so the conversation pane can reuse the
/// existing element instead of recreating it — which is what keeps
/// the `chat-bubble-pop` enter animation from re-firing on every
/// store mutation.
export function bubbleRenderKey(b: ChatBubble, attribution?: string): string {
  const att = b.attachment ? `${b.attachment.mime}:${b.attachment.width}x${b.attachment.height}` : "";
  return `${b.id}|${b.status ?? ""}|${b.failureReason ?? ""}|${b.verified ?? ""}|${b.replyTo?.messageId ?? ""}|${att}|${attribution ?? ""}`;
}

/// Render a bubble. `attribution`, when set, is the sender's display name
/// shown as a small colored label above the bubble — used for the first
/// bubble of each consecutive run in a group so senders are named, not just
/// color-coded. Omitted for DMs, own messages, and follow-on bubbles.
export function renderBubble(
  b: ChatBubble,
  handlers: BubbleHandlers,
  attribution?: string,
): HTMLElement {
  const row = document.createElement("div");
  row.className = `chat-row chat-row--${b.mine ? "out" : "in"}`;
  row.dataset.key = bubbleRenderKey(b, attribution);

  const stack = document.createElement("div");
  stack.className = "chat-bubble__stack";

  // Sender label rides at the very top of the stack, in the sender's identity
  // hue (matching their avatar and bubble stripe), so a group reads as named
  // people at a glance.
  if (attribution) {
    const sender = document.createElement("div");
    sender.className = `chat-bubble__sender ${senderIdentityClass(b.from)}`;
    sender.textContent = attribution;
    stack.appendChild(sender);
  }

  // Quoted parent renders above the body, independent of whether the
  // body itself collapses to an autonomi preview card.
  if (b.replyTo) {
    stack.appendChild(renderQuote(b.replyTo, handlers.onQuoteClick));
  }

  const addresses = extractAutonomiAddresses(b.body);

  const bubble = document.createElement("div");
  bubble.className = "chat-bubble";
  // Per-identity accent on inbound bubbles so senders are distinguishable in a
  // group at a glance — a left stripe + faint tint in the sender's identity
  // hue, matching their avatar. Self keeps the copper out-bubble. The index is
  // deterministic from the sender agent id, so a person looks the same always.
  if (!b.mine) {
    bubble.classList.add(bubbleIdentityClass(b.from));
  }
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
  // Inline image rides at the top of the bubble; any body text becomes
  // its caption underneath. Click opens the full-size view.
  if (b.attachment) {
    bubble.insertBefore(
      renderImageThumb(b.attachment, handlers.onImageOpen),
      bubble.firstChild,
    );
  }
  if (showStatus) {
    bubble.appendChild(statusIcon(b.status as BubbleStatusTag, b.failureReason));
  }
  // Suppress the text bubble entirely when the only content was
  // autonomi:// links — the preview card below already represents
  // the address. Keep it around when there's surrounding text, an
  // inline image, or a sending / failed status indicator.
  if (hasSurroundingText || addresses.length === 0 || showStatus || !!b.attachment) {
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
  if (handlers.onReply) {
    const onReply = handlers.onReply;
    const replyBtn = document.createElement("button");
    replyBtn.type = "button";
    replyBtn.className = "chat-bubble__reply-btn";
    replyBtn.title = "Reply";
    replyBtn.setAttribute("aria-label", "Reply");
    replyBtn.textContent = "↩";
    replyBtn.addEventListener("click", () => onReply(b));
    row.appendChild(replyBtn);
  }
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
/// plain excerpt of the original. Clicking it jumps to the parent when
/// the conversation supplies a handler.
function renderQuote(
  ref: QuotedRef,
  onQuoteClick?: (messageId: string) => void,
): HTMLElement {
  const quote = document.createElement("div");
  quote.className = "chat-quote";
  const who = document.createElement("span");
  who.className = "chat-quote__sender";
  who.textContent = ref.senderName;
  const preview = document.createElement("span");
  preview.className = "chat-quote__preview";
  preview.textContent = ref.preview;
  quote.append(who, preview);
  if (onQuoteClick) {
    quote.classList.add("chat-quote--link");
    quote.title = "Jump to the original message";
    quote.addEventListener("click", () => onQuoteClick(ref.messageId));
  }
  return quote;
}

/// Render the bounded, clickable inline-image thumbnail. The `<img>`
/// renders directly from a `data:` URL built with the validated raster
/// MIME, so the browser decodes it as that image format and never as
/// markup. CSS bounds the displayed size; clicking opens the full view.
function renderImageThumb(
  att: Attachment,
  onOpen?: (att: Attachment) => void,
): HTMLElement {
  const img = document.createElement("img");
  img.className = "chat-attachment";
  img.alt = "image attachment";
  img.draggable = false;
  img.src = attachmentDataUrl(att);
  if (onOpen) {
    img.classList.add("chat-attachment--clickable");
    img.title = "Click to view full size";
    img.addEventListener("click", () => onOpen(att));
  }
  return img;
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
