import type { Rendition } from "../types";
import { el } from "../format";

// M3 G3: placeholder for content whose source address is on the
// community safety denylist. The core render short-circuits to this
// before any decode runs (see HandlerRegistry::render_with_context).
// `reason` is core-generated ("<kind>: <value>") and inserted as a text
// node, never as HTML.
export function renderBlocked(
  r: Extract<Rendition, { kind: "blocked" }>,
  into: HTMLElement,
): void {
  const card = el("div");
  card.className = "blocked-notice";

  const title = el("h2", "Content blocked");
  title.className = "blocked-notice__title";

  const body = el(
    "p",
    "This address is on the community safety denylist and was not rendered.",
  );

  const reason = el("p", r.reason);
  reason.className = "blocked-notice__reason";

  card.appendChild(title);
  card.appendChild(body);
  card.appendChild(reason);
  into.appendChild(card);
}
