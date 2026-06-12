// The M4 fediverse pane: a standalone overlay that hosts the live
// public-post feed. Mirrors the chat panel pattern (fixed overlay,
// header with a glyph + close), but it is placement-agnostic, the host
// element decides docking/position via CSS. Posts are pushed in through
// `add()` by the Tauri public-post event bridge; the pane owns no
// network code of its own.

import { icon } from "../ui/icons";
import { mountCompose } from "./compose";
import { mountFeed } from "./feed";
import type { PublicPostDelivery } from "./feedPost";
import { mountLookup } from "./lookup";

/// Callbacks the host wires into the pane.
export interface FediversePanelHandlers {
  /// Fired when the pane is closed (host hides its launcher affordance).
  onClose: () => void;
  /// Open the LIT Chat DM for a contact imported via the lookup card.
  onOpenDm: (agentIdHex: string) => void;
}

/// Imperative handle over a mounted fediverse pane.
export interface FediversePanelApi {
  open(): void;
  close(): void;
  toggle(): void;
  isOpen(): boolean;
  /// Push one bridged post onto the feed (called by the event bridge).
  add(delivery: PublicPostDelivery): void;
  /// Drop all posts (e.g. on relay reconnect).
  clear(): void;
}

/// Mount the fediverse pane into `host` and return its control handle.
export function mountFediversePanel(
  host: HTMLElement,
  handlers: FediversePanelHandlers,
): FediversePanelApi {
  host.replaceChildren();
  host.className = "fediverse-panel";
  host.hidden = true;

  const header = document.createElement("header");
  header.className = "fediverse-panel__header";

  const glyph = icon("fediverse", { label: "Fediverse" });
  glyph.classList.add("fediverse-panel__icon");

  const title = document.createElement("div");
  title.className = "fediverse-panel__title";
  title.textContent = "Public feed";

  // Honesty chrome on the pane itself: this surface is the third
  // privacy contract (C = observably public), distinct from sealed DMs.
  const note = document.createElement("div");
  note.className = "fediverse-panel__note";
  note.textContent = "Observably public, non-PQ";

  const spacer = document.createElement("div");
  spacer.className = "fediverse-panel__spacer";

  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "fediverse-panel__close chat-icon-btn";
  closeBtn.setAttribute("aria-label", "Close feed");
  closeBtn.title = "Close";
  closeBtn.appendChild(icon("close"));

  header.append(glyph, title, note, spacer, closeBtn);

  const composeHost = document.createElement("div");
  const compose = mountCompose(composeHost);

  // M5.1 handle lookup: pinned between the header and the feed so
  // discovery is the pane's first affordance.
  const lookupHost = document.createElement("div");
  mountLookup(lookupHost, { onOpenDm: handlers.onOpenDm });

  const body = document.createElement("div");
  body.className = "fediverse-panel__body";
  // Reply-publicly on a card targets the compose surface at the
  // relay-verified actor; public reply is the only reply option here.
  const feed = mountFeed(body, (verifiedActorUrl) => compose.setReplyTo(verifiedActorUrl));

  host.append(header, lookupHost, body, composeHost);

  const open = (): void => {
    host.hidden = false;
  };
  const close = (): void => {
    host.hidden = true;
    handlers.onClose();
  };

  closeBtn.addEventListener("click", close);

  return {
    open,
    close,
    toggle: () => (host.hidden ? open() : close()),
    isOpen: () => !host.hidden,
    add: (delivery) => feed.add(delivery),
    clear: () => feed.clear(),
  };
}
