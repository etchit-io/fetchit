import type { Rendition } from "../types";
import { el } from "../format";

const HEX_64 = /^[0-9a-f]{64}$/i;

function profileAgentId(pretty: string): string | null {
  try {
    const v = JSON.parse(pretty) as Record<string, unknown>;
    if (v.version === 1 && typeof v.agent_id === "string" && HEX_64.test(v.agent_id)
      && typeof v.sig === "string" && typeof v.ml_dsa_pubkey === "string") {
      return v.agent_id.toLowerCase();
    }
  } catch { /* not json-of-interest */ }
  return null;
}

export function renderJson(
  r: Extract<Rendition, { kind: "json" }>,
  into: HTMLElement,
  onViewProfile?: (agentId: string) => void,
): void {
  const agentId = profileAgentId(r.pretty);
  if (agentId && onViewProfile) {
    const banner = document.createElement("div");
    banner.className = "json-profile-banner";
    banner.textContent = "This looks like a profile. ";
    const view = document.createElement("button");
    view.type = "button";
    view.dataset.act = "view-as-profile";
    view.textContent = "View as profile page";
    view.addEventListener("click", () => onViewProfile(agentId));
    banner.appendChild(view);
    into.appendChild(banner);
  }
  into.appendChild(el("pre", r.pretty));
}
