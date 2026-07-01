// Add-contact dialog — accepts a pasted pointer URI (`x0x://pair/…`),
// a v2 `x0x://agent/…` card URI, a v3 `fetchit://share/v3/…` profile
// share URI, or a fediverse handle (`@name@domain`, M5.1) and forwards
// it to the matching daemon command. A handle resolves through
// `fediverse_lookup`; only a verified fetch>it identity imports.

import { lookupHandle } from "../fediverse/api";
import { importCard, importPairUri, pairAccept } from "./api";
import { friendlyError } from "./errors";

export interface AddContactHandlers {
  onClose: () => void;
  /// Called after a successful add. The optional `agentIdHex` is set
  /// for v3 accepts so the caller can navigate to the new DM; v2
  /// imports get `undefined` (the daemon emits the contact through
  /// the normal refresh path either way).
  onImported: (result?: { agentIdHex: string }) => void;
}

type InputKind = "pointer" | "v2" | "v3" | "handle";

const POINTER_PREFIX = "x0x://pair/";
const V2_PREFIX = "x0x://agent/";
const V3_PREFIX = "fetchit://share/v3/";
const HANDLE_RE = /^@[^@\s]+@[^@\s]+\.[^@\s]+$/;

function detectInputKind(value: string): InputKind | null {
  const t = value.trim();
  if (t.startsWith(POINTER_PREFIX)) return "pointer";
  if (t.startsWith(V2_PREFIX)) return "v2";
  if (t.startsWith(V3_PREFIX)) return "v3";
  if (HANDLE_RE.test(t)) return "handle";
  return null;
}

export function mountAddContact(
  root: HTMLElement,
  handlers: AddContactHandlers,
): void {
  root.replaceChildren();
  root.className = "chat-dialog";

  const inner = document.createElement("div");
  inner.className = "chat-dialog__panel";

  const title = document.createElement("h3");
  title.textContent = "Add a contact";

  const help = document.createElement("p");
  help.className = "chat-dialog__help";
  help.textContent
    = "Paste a share link from someone you trust, "
      + "or type their handle like @name@etchit.io";

  // Share URIs are long (KEM/ML-DSA keys + signature add up to ~17KB).
  // A single-line <input> forces the text engine to lay out the entire
  // value on one line and crashes the Wayland Cairo surface allocator
  // past 65535 px; textarea wraps visually and keeps the box bounded.
  const input = document.createElement("textarea");
  input.className = "chat-dialog__uri";
  input.placeholder = "Paste a share link, or @name@etchit.io";
  input.spellcheck = false;
  input.rows = 4;
  input.wrap = "soft";
  input.setAttribute("aria-label", "Share link");

  const status = document.createElement("p");
  status.className = "chat-dialog__status";

  const actions = document.createElement("div");
  actions.className = "chat-dialog__actions";

  const addBtn = document.createElement("button");
  addBtn.type = "button";
  addBtn.className = "chat-dialog__btn";
  addBtn.textContent = "Add";
  addBtn.disabled = true;

  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "chat-dialog__btn chat-dialog__btn--ghost";
  closeBtn.textContent = "Cancel";
  closeBtn.addEventListener("click", handlers.onClose);

  actions.appendChild(addBtn);
  actions.appendChild(closeBtn);

  inner.appendChild(title);
  inner.appendChild(help);
  inner.appendChild(input);
  inner.appendChild(status);
  inner.appendChild(actions);
  root.appendChild(inner);

  root.addEventListener("click", (e) => {
    if (e.target === root) handlers.onClose();
  });

  input.addEventListener("input", () => {
    addBtn.disabled = detectInputKind(input.value) === null;
    status.textContent = "";
  });

  addBtn.addEventListener("click", async () => {
    const kind = detectInputKind(input.value);
    if (kind === null) return;
    addBtn.disabled = true;
    status.textContent = inFlightStatus(kind);
    try {
      const uri = input.value.trim();
      if (kind === "handle") {
        const dto = await lookupHandle(uri);
        if (dto.kind !== "verified" || !dto.shareUri) {
          status.textContent = dto.verifyFailure
            ? `Couldn't verify that handle: ${dto.verifyFailure}`
            : "That account isn't linked to a fetch>it identity, so it can't "
              + "be added as a private contact.";
          addBtn.disabled = false;
          return;
        }
        const result = await pairAccept(dto.shareUri);
        status.textContent = "Imported.";
        handlers.onImported(result);
      } else if (kind === "v3") {
        const result = await pairAccept(uri);
        status.textContent = "Imported.";
        handlers.onImported(result);
      } else if (kind === "pointer") {
        await importPairUri(uri);
        status.textContent = "Imported.";
        handlers.onImported();
      } else {
        await importCard(uri);
        status.textContent = "Imported.";
        handlers.onImported();
      }
    } catch (e) {
      status.textContent = importErrorCopy(kind, e);
      addBtn.disabled = false;
    }
  });

  setTimeout(() => input.focus(), 0);
}

/// In-flight status copy while an add is resolving, keyed by input kind.
function inFlightStatus(kind: InputKind): string {
  if (kind === "handle") return "Looking up handle…";
  if (kind === "v3") return "Fetching profile…";
  if (kind === "pointer") return "Looking them up…";
  return "Importing…";
}

/// Honest, plain-English failure copy. For a pointer URI the common
/// failure is an unreachable relay, so the message tells the user the
/// actionable next step: ask the contact to re-share.
function importErrorCopy(kind: InputKind, e: unknown): string {
  if (kind === "pointer") {
    return `Couldn't reach their relay — ask them to re-share. (${friendlyError(e)})`;
  }
  return `Failed: ${friendlyError(e)}`;
}
