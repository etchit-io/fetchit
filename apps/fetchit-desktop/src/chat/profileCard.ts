import type { ProfileOutcome } from "./types";
import { avatarGradientClass } from "./avatarColor";

export interface ProfileCardOpts {
  agentId: string;
  fetchProfile: (agentId: string) => Promise<ProfileOutcome>;
  fetchAvatar: (addr: string, mime: string, bytesLen: number) => Promise<string>;
  /// Open a 64-hex Autonomi address in the reader (caller closes chat).
  onAutonomi: (uri: string) => void;
  /// The contact themselves (x0x link) -- caller is already in the DM.
  onMessage: (agentId: string) => void;
  /// External https website -- caller shows a confirm then system-opens.
  confirmOpen: (url: string) => void;
  /// Navigate to the full profile page for this agent (caller may close chat).
  onOpenFullProfile: (agentId: string) => void;
}

interface Host {
  host: HTMLDivElement;
  body: HTMLDivElement;
}
let ref: Host | null = null;

function ensureHost(): Host {
  if (ref) return ref;
  const host = document.createElement("div");
  host.className = "chat-profile";
  host.hidden = true;
  const panel = document.createElement("div");
  panel.className = "chat-profile__panel";
  const close = document.createElement("button");
  close.type = "button";
  close.className = "chat-profile__close";
  close.setAttribute("aria-label", "Close");
  close.textContent = "×";
  close.addEventListener("click", () => closeCard());
  const body = document.createElement("div");
  body.className = "chat-profile__body";
  panel.append(close, body);
  host.appendChild(panel);
  document.body.appendChild(host);
  host.addEventListener("click", (e) => {
    if (e.target === host) closeCard();
  });
  ref = { host, body };
  return ref;
}

function closeCard(): void {
  if (!ref) return;
  ref.host.hidden = true;
  ref.body.replaceChildren();
}

function line(cls: string, text: string): HTMLElement {
  const el = document.createElement("div");
  el.className = cls;
  el.textContent = text;
  return el;
}

export function openProfileCard(opts: ProfileCardOpts): void {
  const { host, body } = ensureHost();
  body.replaceChildren(line("chat-profile__loading", "Loading profile…"));
  host.hidden = false;

  void opts
    .fetchProfile(opts.agentId)
    .then((outcome) => {
      if (outcome.kind === "none") {
        body.replaceChildren(
          line("chat-profile__empty", "This contact hasn't published a profile yet."),
        );
        return;
      }
      renderLoaded(body, outcome, opts);
    })
    .catch((e: unknown) => {
      const msg = e instanceof Error ? e.message : "this profile could not be loaded";
      body.replaceChildren(line("chat-profile__error", msg));
    });
}

function renderLoaded(
  body: HTMLElement,
  p: Extract<ProfileOutcome, { kind: "profile" }>,
  opts: ProfileCardOpts,
): void {
  body.replaceChildren();

  const avatarBox = document.createElement("div");
  avatarBox.className = "chat-profile__avatar";
  avatarBox.classList.add(avatarGradientClass(opts.agentId));
  body.appendChild(avatarBox);
  if (p.avatar) {
    const a = p.avatar;
    void opts
      .fetchAvatar(a.addr, a.mime, a.bytesLen)
      .then((dataUrl) => {
        const img = document.createElement("img");
        img.alt = "avatar";
        img.draggable = false;
        img.src = dataUrl;
        avatarBox.replaceChildren(img);
      })
      .catch(() => {
        /* leave the placeholder box */
      });
  }

  body.appendChild(line("chat-profile__name", p.displayName));

  const full = document.createElement("button");
  full.type = "button";
  full.className = "chat-profile__full";
  full.textContent = "Open full profile";
  full.addEventListener("click", () => { closeCard(); opts.onOpenFullProfile(opts.agentId); });
  body.appendChild(full);

  if (p.bio) body.appendChild(line("chat-profile__bio", p.bio));

  if (p.website) {
    const w = document.createElement("button");
    w.type = "button";
    w.className = "chat-profile__website";
    w.textContent = p.website;
    const url = p.website;
    w.addEventListener("click", () => opts.confirmOpen(url));
    body.appendChild(w);
  }

  const links = document.createElement("div");
  links.className = "chat-profile__links";
  for (const l of p.links) {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "chat-profile__link";
    chip.dataset.kind = l.kind;
    chip.textContent = l.label || l.kind;
    chip.addEventListener("click", () => routeLink(l.kind, l.addr, opts));
    links.appendChild(chip);
  }
  if (p.links.length > 0) body.appendChild(links);
}

function routeLink(kind: string, addr: string, opts: ProfileCardOpts): void {
  if (kind === "etchit" || kind === "fetchit" || kind === "image") {
    closeCard();
    opts.onAutonomi(`autonomi://${addr}`);
  } else if (kind === "x0x") {
    closeCard();
    opts.onMessage(addr);
  } else if (kind === "website") {
    opts.confirmOpen(addr);
  }
}
