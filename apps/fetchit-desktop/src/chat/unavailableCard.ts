// Human card for a failed chat bootstrap, branched on cause. The
// keystore branch points at the passphrase escape hatch; everything
// else is framed as transient (the panel's retry loop keeps running).

export type ChatUnavailableKind = "keystore" | "transient";

export const CHAT_UNAVAILABLE_COPY = {
  keystore:
    "Chat can't start on this computer. It needs your system's secure "
    + "key storage, which isn't available right now. Reading works fully "
    + "without it.",
  keystoreAction: "To use chat anyway, set a chat passphrase in Settings > Advanced.",
  transient:
    "Chat can't start right now. It usually fixes itself in a moment, "
    + "and reading works fully in the meantime.",
} as const;

export function classifyBootstrapError(e: unknown): ChatUnavailableKind {
  return /keyring/i.test(String(e)) ? "keystore" : "transient";
}

/// Render (or replace) the card inside `host`. Idempotent per host.
export function renderChatUnavailableCard(
  host: HTMLElement,
  kind: ChatUnavailableKind,
): HTMLElement {
  host.querySelector(".chat-unavailable")?.remove();
  const card = document.createElement("div");
  card.className = "chat-unavailable";
  const msg = document.createElement("p");
  msg.className = "chat-unavailable__msg";
  msg.textContent = CHAT_UNAVAILABLE_COPY[kind];
  card.append(msg);
  if (kind === "keystore") {
    const action = document.createElement("p");
    action.className = "chat-unavailable__action";
    action.textContent = CHAT_UNAVAILABLE_COPY.keystoreAction;
    card.append(action);
  }
  host.prepend(card);
  return card;
}
