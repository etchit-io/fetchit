// The M4 fediverse pane: a standalone overlay that hosts the live
// public-post feed. Mirrors the chat panel pattern (fixed overlay,
// header with a glyph + close), but it is placement-agnostic, the host
// element decides docking/position via CSS. Posts are pushed in through
// `add()` by the Tauri public-post event bridge; the pane owns no
// network code of its own.

import { icon } from "../ui/icons";
import { mountFeed } from "./feed";
import type { PublicPostDelivery } from "./feedPost";

/// Callbacks the host wires into the pane.
export interface FediversePanelHandlers {
  /// Fired when the pane is closed (host hides its launcher affordance).
  onClose: () => void;
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

  const body = document.createElement("div");
  body.className = "fediverse-panel__body";
  const feed = mountFeed(body);

  host.append(header, body);

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
