// "Share your card" dialog. Tries the v3 profile share URI first (short,
// always-scannable, anchored to the user's Autonomi profile); falls back
// silently to the v2 extended share URI when no v3 profile has been
// published yet. The user only ever sees the best available payload.

import { myCard, pairShare } from "./api";
import { friendlyError } from "./errors";
import { renderQrSvg } from "../qr";

export interface CardDialogHandlers {
  onClose: () => void;
  /// Persist a user-typed display name. Called after the input loses
  /// focus or the user hits Enter. Resolves once settings is written.
  /// Only fires in v2 mode — v3 display name lives in the published
  /// profile and is edited in etch>it.
  onRename: (name: string) => Promise<void>;
}

export async function mountCardDialog(
  root: HTMLElement,
  displayName: string,
  handlers: CardDialogHandlers,
): Promise<void> {
  root.replaceChildren();
  root.className = "chat-dialog";

  const inner = document.createElement("div");
  inner.className = "chat-dialog__panel";

  const title = document.createElement("h3");
  title.textContent = "Your share card";

  const nameLabel = document.createElement("label");
  nameLabel.className = "chat-dialog__help";
  nameLabel.textContent = "Display name (visible to people you chat with)";

  const nameInput = document.createElement("input");
  nameInput.className = "chat-dialog__uri";
  nameInput.type = "text";
  nameInput.value = displayName;
  nameInput.spellcheck = false;
  nameInput.placeholder = "How you appear to others";
  nameInput.setAttribute("aria-label", "Display name");

  const v3Note = document.createElement("p");
  v3Note.className = "chat-dialog__help";
  v3Note.textContent
    = "Sharing your Autonomi profile — edit your display name and bio in etch>it.";
  v3Note.hidden = true;

  const status = document.createElement("p");
  status.className = "chat-dialog__status";
  status.textContent = "Generating…";

  const qrHost = document.createElement("div");
  qrHost.className = "chat-dialog__qr";
  qrHost.setAttribute("aria-hidden", "true");

  // Textarea (not input) so a multi-KB URI wraps visually — a
  // single-line input would force the text engine to lay out the
  // entire value on one line and crash the Wayland Cairo allocator.
  const uriBox = document.createElement("textarea");
  uriBox.className = "chat-dialog__uri";
  uriBox.readOnly = true;
  uriBox.rows = 4;
  uriBox.wrap = "soft";
  uriBox.setAttribute("aria-label", "Share URI");

  const actions = document.createElement("div");
  actions.className = "chat-dialog__actions";

  const copyBtn = document.createElement("button");
  copyBtn.type = "button";
  copyBtn.className = "chat-dialog__btn";
  copyBtn.textContent = "Copy URI";

  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "chat-dialog__btn chat-dialog__btn--ghost";
  closeBtn.textContent = "Close";
  closeBtn.addEventListener("click", handlers.onClose);

  actions.appendChild(copyBtn);
  actions.appendChild(closeBtn);

  inner.appendChild(title);
  inner.appendChild(nameLabel);
  inner.appendChild(nameInput);
  inner.appendChild(v3Note);
  inner.appendChild(status);
  inner.appendChild(qrHost);
  inner.appendChild(uriBox);
  inner.appendChild(actions);
  root.appendChild(inner);

  root.addEventListener("click", (e) => {
    if (e.target === root) handlers.onClose();
  });

  let currentName = displayName;
  let mode: "v2" | "v3" = "v2";

  const paintQr = (uri: string): void => {
    qrHost.replaceChildren();
    // QR is best-effort. v2 cards carry a KEM pubkey + sigs and can
    // exceed any QR version's capacity; in that case fall back to a
    // textual notice so the URI itself stays usable.
    try {
      qrHost.replaceChildren(renderQrSvg(uri));
    } catch {
      const notice = document.createElement("p");
      notice.className = "chat-dialog__help";
      notice.textContent = "URI too large for a QR — use Copy URI instead.";
      qrHost.replaceChildren(notice);
    }
  };

  const applyMode = (next: "v2" | "v3"): void => {
    mode = next;
    const v3 = next === "v3";
    nameLabel.hidden = v3;
    nameInput.hidden = v3;
    v3Note.hidden = !v3;
  };

  const regenerateV2 = async (name: string): Promise<void> => {
    status.textContent = "Generating…";
    qrHost.replaceChildren();
    uriBox.value = "";
    try {
      const result = await myCard(name);
      status.textContent
        = `${result.card.display_name} · ${result.card.agent_id.slice(0, 8)}…`;
      uriBox.value = result.uri;
      paintQr(result.uri);
    } catch (e) {
      status.textContent = `Could not generate card: ${friendlyError(e)}`;
    }
  };

  const applyRename = async (): Promise<void> => {
    if (mode !== "v2") return;
    const next = nameInput.value.trim();
    if (next === currentName.trim()) return;
    currentName = next;
    try {
      await handlers.onRename(next);
    } catch (e) {
      console.warn("[chat] save display name:", e);
    }
    await regenerateV2(next);
  };

  nameInput.addEventListener("change", () => {
    void applyRename();
  });
  nameInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      nameInput.blur();
    }
  });

  copyBtn.addEventListener("click", async () => {
    if (!uriBox.value) return;
    try {
      await navigator.clipboard.writeText(uriBox.value);
      copyBtn.textContent = "Copied";
      setTimeout(() => {
        copyBtn.textContent = "Copy URI";
      }, 1200);
    } catch {
      uriBox.select();
      document.execCommand("copy");
    }
  });

  // Feature-detect v3 first. Any failure (404 "publish your profile",
  // network error, malformed record, empty payload) falls back to v2
  // silently — the user gets the best payload the local state can
  // produce, and never sees a "success" state with nothing to share.
  try {
    const v3Uri = await pairShare();
    if (!v3Uri) throw new Error("empty v3 share URI");
    applyMode("v3");
    status.textContent = "Pointed at your Autonomi profile.";
    uriBox.value = v3Uri;
    paintQr(v3Uri);
  } catch {
    applyMode("v2");
    await regenerateV2(displayName);
  }
}
