// Per-contact trust controls in the conversation header: a select for
// the four trust levels, plus a small Remove button that confirms
// before nuking the contact and its local transcript.

import { chatConfirm } from "./confirmDialog";
import type { Contact, TrustLevel } from "./types";

export interface TrustMenuHandlers {
  onSetTrust: (level: TrustLevel) => void;
  onRemove: () => void;
}

const LEVELS: TrustLevel[] = ["blocked", "unknown", "known", "trusted"];

export function mountTrustMenu(
  parent: HTMLElement,
  contact: Contact,
  handlers: TrustMenuHandlers,
): void {
  parent.replaceChildren();
  parent.className = "chat-trust";

  const select = document.createElement("select");
  select.className = "chat-trust__select";
  select.setAttribute("aria-label", "Trust level");
  for (const level of LEVELS) {
    const opt = document.createElement("option");
    opt.value = level;
    opt.textContent = labelFor(level);
    select.appendChild(opt);
  }
  select.value = contact.trust_level;
  select.addEventListener("change", () => {
    handlers.onSetTrust(select.value as TrustLevel);
  });

  const removeBtn = document.createElement("button");
  removeBtn.type = "button";
  removeBtn.className = "chat-trust__remove";
  removeBtn.title = "Remove contact";
  removeBtn.setAttribute("aria-label", "Remove contact");
  removeBtn.textContent = "Remove";
  removeBtn.addEventListener("click", () => {
    const label = contact.label ?? contact.display_name ?? contact.agent_id;
    void (async () => {
      const ok = await chatConfirm({
        title: "Remove contact",
        message: `Remove ${label}? Their local message history will be deleted.`,
        confirmLabel: "Remove",
      });
      if (ok) handlers.onRemove();
    })();
  });

  parent.appendChild(select);
  parent.appendChild(removeBtn);
}

function labelFor(level: TrustLevel): string {
  switch (level) {
    case "blocked":
      return "Blocked";
    case "unknown":
      return "Unknown";
    case "known":
      return "Known";
    case "trusted":
      return "Trusted";
  }
}
