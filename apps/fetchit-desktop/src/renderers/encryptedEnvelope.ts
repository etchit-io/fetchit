import type { Rendition } from "../types";
import { el } from "../format";

// A recognised saorsa-mls/v1 envelope: the ciphertext is public and
// permanent, the keys are not ours. Render an honest card instead of
// garbage bytes. The group hint is publisher-chosen text and is
// inserted as a text node, never as HTML.
export function renderEncryptedEnvelope(
  r: Extract<Rendition, { kind: "encryptedEnvelope" }>,
  into: HTMLElement,
): void {
  const card = el("div");
  card.className = "encrypted-notice";

  const title = el("h2", "Encrypted content");
  title.className = "encrypted-notice__title";
  card.appendChild(title);

  const body = el(
    "p",
    "This address holds a saorsa-mls encrypted envelope. fetch>it holds no keys and cannot decrypt it.",
  );
  card.appendChild(body);

  if (r.groupHint) {
    const hint = el("p", `Group: ${r.groupHint}`);
    hint.className = "encrypted-notice__hint";
    card.appendChild(hint);
  }

  const size = el("p", `Ciphertext: ${r.ciphertextLen.toLocaleString()} bytes`);
  size.className = "encrypted-notice__size";
  card.appendChild(size);

  into.appendChild(card);
}
