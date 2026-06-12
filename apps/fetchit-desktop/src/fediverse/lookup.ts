// M5.1 handle lookup: one search box, two outcomes. The verified card
// carries the private affordances; both run EXISTING chat flows
// (chat_pair_accept on the synthesized v3 share URI, the standard
// group-invite URI delivered over a DM). The public-only card never
// renders a private affordance, and a failed attestation is shown,
// not hidden.

import { groupInvite, listGroups, pairAccept, sendDm } from "../chat/api";
import { errMsg } from "../chat/errors";
import { lookupHandle, type LookupResult } from "./api";

export interface LookupHandlers {
  /// Open the LIT Chat DM for an imported contact.
  onOpenDm: (agentIdHex: string) => void;
}

const HANDLE_RE = /^@[^@\s]+@[^@\s]+\.[^@\s]+$/;

export function mountLookup(host: HTMLElement, handlers: LookupHandlers): void {
  host.classList.add("fediverse-lookup");

  const form = document.createElement("div");
  form.className = "fediverse-lookup__form";

  const input = document.createElement("input");
  input.type = "text";
  input.className = "fediverse-lookup__input";
  input.placeholder = "Find someone: @handle@domain";
  input.spellcheck = false;

  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "fediverse-lookup__btn";
  btn.textContent = "Look up";

  const results = document.createElement("div");
  results.className = "fediverse-lookup__results";

  form.append(input, btn);
  host.append(form, results);

  const run = async (): Promise<void> => {
    const handle = input.value.trim();
    if (!HANDLE_RE.test(handle)) {
      results.replaceChildren(errorLine("Type a full handle, like @name@etchit.io"));
      return;
    }
    btn.disabled = true;
    results.replaceChildren(line("fediverse-lookup__loading", `Looking up ${handle}…`));
    try {
      const dto = await lookupHandle(handle);
      results.replaceChildren(renderActorCard(dto, handlers));
    } catch (e) {
      results.replaceChildren(errorLine(errMsg(e)));
    } finally {
      btn.disabled = false;
    }
  };

  btn.addEventListener("click", () => void run());
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") void run();
  });
}

function line(className: string, text: string): HTMLElement {
  const el = document.createElement("div");
  el.className = className;
  el.textContent = text;
  return el;
}

function errorLine(text: string): HTMLElement {
  return line("fediverse-lookup__error", text);
}

/// Render one lookup outcome as an actor card. Exported for reuse by
/// the M5.3 directory-search results.
export function renderActorCard(dto: LookupResult, handlers: LookupHandlers): HTMLElement {
  const card = document.createElement("article");
  card.className = `actor-card actor-card--${dto.kind === "verified" ? "verified" : "public"}`;

  const name = line("actor-card__name", dto.displayName ?? dto.handle);
  const handle = line("actor-card__handle", dto.handle);
  handle.title = dto.actorUrl;
  card.append(name, handle);

  if (dto.kind === "verified" && dto.agentIdHex && dto.shareUri) {
    renderVerified(card, dto as VerifiedDto, handlers);
  } else if (dto.verifyFailure) {
    card.append(
      line(
        "actor-card__warn",
        `Couldn't verify this account's fetch>it identity (${dto.verifyFailure}). `
          + "Private messaging is disabled for it.",
      ),
    );
  } else {
    card.append(
      line(
        "actor-card__note",
        "This account hasn't linked a fetch>it identity, so private messaging "
          + "isn't available. You can follow them from any fediverse app.",
      ),
    );
  }
  return card;
}

type VerifiedDto = LookupResult & { agentIdHex: string; shareUri: string };

function renderVerified(card: HTMLElement, dto: VerifiedDto, handlers: LookupHandlers): void {
  if (dto.bio) card.append(line("actor-card__bio", dto.bio));

  const badge = line("actor-card__badge", "Verified fetch>it identity");
  const agent = line("actor-card__agent", `agent ${dto.agentIdHex.slice(0, 8)}…`);
  agent.title = dto.agentIdHex;
  card.append(badge, agent);

  if (dto.previousAgentIdHex) {
    card.append(
      line(
        "actor-card__warn",
        "This handle changed hands: it previously belonged to a different "
          + "identity. Any existing contact of yours is unaffected; treat this "
          + "as a new person.",
      ),
    );
  }

  const status = line("actor-card__status", "");
  const actions = document.createElement("div");
  actions.className = "actor-card__actions";

  const msgBtn = document.createElement("button");
  msgBtn.type = "button";
  msgBtn.className = "actor-card__msg-btn";
  msgBtn.textContent = "Message privately";
  msgBtn.addEventListener("click", () => {
    msgBtn.disabled = true;
    status.textContent = "Adding contact…";
    pairAccept(dto.shareUri)
      .then((r) => {
        status.textContent = "Added to contacts.";
        handlers.onOpenDm(r.agentIdHex);
      })
      .catch((e: unknown) => {
        status.textContent = `Couldn't add contact: ${errMsg(e)}`;
        msgBtn.disabled = false;
      });
  });

  const inviteBtn = document.createElement("button");
  inviteBtn.type = "button";
  inviteBtn.className = "actor-card__invite-btn";
  inviteBtn.textContent = "Invite to group";
  inviteBtn.addEventListener("click", () => {
    inviteBtn.disabled = true;
    void mountInviteRow(card, dto, status).finally(() => {
      inviteBtn.disabled = false;
    });
  });

  actions.append(msgBtn, inviteBtn);
  card.append(actions, status);
}

async function mountInviteRow(
  card: HTMLElement,
  dto: VerifiedDto,
  status: HTMLElement,
): Promise<void> {
  card.querySelector(".actor-card__invite-row")?.remove();
  let groups;
  try {
    groups = await listGroups();
  } catch (e) {
    status.textContent = `Couldn't load groups: ${errMsg(e)}`;
    return;
  }
  if (groups.length === 0) {
    status.textContent = "No groups yet. Create one in LIT Chat first.";
    return;
  }

  const row = document.createElement("div");
  row.className = "actor-card__invite-row";

  const select = document.createElement("select");
  select.className = "actor-card__invite-select";
  for (const g of groups) {
    const opt = document.createElement("option");
    opt.value = g.group_id;
    opt.textContent = g.name ?? `group ${g.group_id.slice(0, 8)}…`;
    select.appendChild(opt);
  }

  const send = document.createElement("button");
  send.type = "button";
  send.className = "actor-card__invite-send";
  send.textContent = "Send invite";
  send.addEventListener("click", () => {
    send.disabled = true;
    status.textContent = "Sending invite…";
    const groupName = select.selectedOptions[0]?.textContent ?? "a group";
    void (async () => {
      try {
        const imported = await pairAccept(dto.shareUri);
        const uri = await groupInvite(select.value);
        await sendDm(imported.agentIdHex, `Join "${groupName}" on LIT Chat: ${uri}`);
        status.textContent = "Invite sent.";
        row.remove();
      } catch (e) {
        status.textContent = `Couldn't send the invite: ${errMsg(e)}`;
        send.disabled = false;
      }
    })();
  });

  row.append(select, send);
  card.appendChild(row);
}
