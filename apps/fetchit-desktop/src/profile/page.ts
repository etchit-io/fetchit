import type { ProfilePageModel } from "./open";
import { avatarGradientClass } from "../chat/avatarColor";

export interface ProfilePageHandlers {
  onAutonomi: (uri: string) => void;
  onMessage: (m: ProfilePageModel) => void;
  onInvite: (m: ProfilePageModel) => void;
  onShare: (m: ProfilePageModel) => void;
  onEditEtch: () => void;
  onGetEtch: () => void;
  confirmOpen: (url: string) => void;
}

type Avatar = (addr: string, mime: string, bytesLen: number) => Promise<string>;

function line(cls: string, text: string): HTMLElement {
  const el = document.createElement("div");
  el.className = cls;
  el.textContent = text;
  return el;
}

function btn(act: string, cls: string, text: string, on: () => void): HTMLButtonElement {
  const b = document.createElement("button");
  b.type = "button";
  b.className = cls;
  b.dataset.act = act;
  b.textContent = text;
  b.addEventListener("click", on);
  return b;
}

export function renderProfilePage(
  model: ProfilePageModel,
  root: HTMLElement,
  h: ProfilePageHandlers,
  fetchAvatar: Avatar,
): void {
  root.replaceChildren();
  root.classList.add("profile-page");

  if (model.state === "error") {
    root.appendChild(line("profile-page__error", model.error ?? "this profile could not be loaded"));
    return;
  }

  const band = document.createElement("header");
  band.className = "profile-page__band";

  const avatar = document.createElement("div");
  avatar.className = "profile-page__avatar";
  if (model.agentId) avatar.classList.add(avatarGradientClass(model.agentId));
  band.appendChild(avatar);
  if (model.avatar) {
    const a = model.avatar;
    void fetchAvatar(a.addr, a.mime, a.bytesLen)
      .then((url) => {
        const img = document.createElement("img");
        img.alt = "avatar";
        img.draggable = false;
        img.src = url;
        avatar.replaceChildren(img);
      })
      .catch(() => {});
  }

  const idCol = document.createElement("div");
  idCol.className = "profile-page__id";
  const nameRow = document.createElement("div");
  nameRow.className = "profile-page__namerow";
  nameRow.appendChild(line("profile-page__name", model.display));
  if (model.verified) nameRow.appendChild(line("profile-page__badge", "verified identity"));
  idCol.appendChild(nameRow);
  if (model.handle) idCol.appendChild(line("profile-page__handle", model.handle));
  band.appendChild(idCol);

  band.appendChild(buildActions(model, h));
  root.appendChild(band);

  if (model.changedHands) {
    root.appendChild(line("profile-page__changed",
      "This handle previously pointed to different keys. Treat this as a new person."));
  }
  if (model.state === "publicOnly" && model.verifyFailure) {
    root.appendChild(line("profile-page__verify-fail",
      `Identity could not be verified (${model.verifyFailure}). Private messaging is off.`));
  }
  if (model.bio) root.appendChild(line("profile-page__bio", model.bio));
  if (model.website) {
    const w = btn("website", "profile-page__website", model.website, () => h.confirmOpen(model.website as string));
    root.appendChild(w);
  }

  const HEX_KINDS = new Set(["etchit", "fetchit", "image"]);
  const gallery = model.links.filter((l) => HEX_KINDS.has(l.kind));
  const chips = model.links.filter((l) => !HEX_KINDS.has(l.kind));

  if (gallery.length > 0) {
    root.appendChild(line("profile-page__label", "Etchings"));
    const grid = document.createElement("div");
    grid.className = "profile-page__gallery";
    for (const l of gallery) {
      const card = document.createElement("button");
      card.type = "button";
      card.className = "profile-page__etch";
      card.dataset.kind = l.kind;
      card.append(line("profile-page__etch-kind", l.kind), line("profile-page__etch-label", l.label || l.kind));
      card.addEventListener("click", () => h.onAutonomi(`autonomi://${l.addr}`));
      grid.appendChild(card);
    }
    root.appendChild(grid);
  }
  if (chips.length > 0) {
    const row = document.createElement("div");
    row.className = "profile-page__chips";
    for (const l of chips) {
      const chip = document.createElement("button");
      chip.type = "button";
      chip.className = "profile-page__chip";
      chip.textContent = l.label || l.kind;
      chip.addEventListener("click", () => {
        if (l.kind === "website") h.confirmOpen(l.addr);
      });
      row.appendChild(chip);
    }
    root.appendChild(row);
  }
}

function buildActions(model: ProfilePageModel, h: ProfilePageHandlers): HTMLElement {
  const row = document.createElement("div");
  row.className = "profile-page__actions";
  if (model.isSelf) {
    row.appendChild(btn("edit-etch", "profile-page__act", "Edit in etch/it", h.onEditEtch));
  } else if (model.verified && model.agentId) {
    row.appendChild(btn("message", "profile-page__act profile-page__act--primary", "Message", () => h.onMessage(model)));
    row.appendChild(btn("invite", "profile-page__act", "Invite to group", () => h.onInvite(model)));
  }
  if (model.agentId) {
    row.appendChild(btn("share", "profile-page__act", "Share", () => h.onShare(model)));
  }
  return row;
}
