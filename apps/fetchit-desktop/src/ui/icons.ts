// Inline SVG icon set for the chat + reader chrome. One source for
// every chrome glyph, replacing the ad-hoc unicode characters the UI
// leaned on before. Each icon is a static, hand-authored SVG that uses
// `currentColor` only, so it inherits the host element's color token
// and recolors with the theme. Parsed via `DOMParser` (no script
// evaluation, no XSS) exactly like the mascot scene. No icon font, no
// network asset.

/// Every named glyph the chrome can render. Derived from `ICON_NAMES`
/// so the list and the type can never drift apart.
export type IconName = (typeof ICON_NAMES)[number];

/// The canonical glyph list. Iterated by the test-suite to assert every
/// icon is well-formed and theme-safe.
export const ICON_NAMES = [
  "send",
  "attach",
  "emoji",
  "react",
  "reply",
  "close",
  "dock",
  "settings",
  "add-contact",
  "new-group",
  "join-group",
  "chat",
  "fediverse",
  "image",
  "back",
  "bookmark",
  "share",
  "chevron",
] as const;

// 24x24 grid, 2px stroke, round joins (set on the shared wrapper). Each
// entry is the inner markup: `<path>` / `<circle>` / `<line>` primitives
// using `currentColor` only. Filled accents (eyes, knobs) opt in with
// `fill="currentColor" stroke="none"`; everything else strokes.
const BODY: Record<IconName, string> = {
  send: '<path d="M22 2 11 13" /><path d="M22 2 15 22 11 13 2 9 22 2Z" />',
  attach:
    '<path d="M20.5 11.5 12 20a5 5 0 0 1-7.1-7.1l8.5-8.5a3.3 3.3 0 0 1 4.7 4.7l-8.5 8.5a1.6 1.6 0 0 1-2.3-2.3l7.8-7.8" />',
  emoji:
    '<circle cx="12" cy="12" r="9" /><circle cx="9" cy="10" r="1.1" fill="currentColor" stroke="none" /><circle cx="15" cy="10" r="1.1" fill="currentColor" stroke="none" /><path d="M8.5 14a4.5 4.5 0 0 0 7 0" />',
  react:
    '<circle cx="11" cy="13" r="8" /><circle cx="8.5" cy="11" r="1" fill="currentColor" stroke="none" /><circle cx="13.5" cy="11" r="1" fill="currentColor" stroke="none" /><path d="M7.7 15a4 4 0 0 0 6.6 0" /><path d="M19 3v4M17 5h4" />',
  reply: '<path d="M9 7 4 12l5 5" /><path d="M4 12h10a6 6 0 0 1 6 6v1" />',
  close: '<path d="M18 6 6 18" /><path d="M6 6l12 12" />',
  dock: '<rect x="3" y="4" width="18" height="16" rx="2" /><line x1="14" y1="4" x2="14" y2="20" />',
  settings:
    '<line x1="4" y1="8" x2="20" y2="8" /><line x1="4" y1="16" x2="20" y2="16" /><circle cx="9" cy="8" r="2.3" fill="currentColor" stroke="none" /><circle cx="15" cy="16" r="2.3" fill="currentColor" stroke="none" />',
  "add-contact":
    '<circle cx="9" cy="8" r="3.5" /><path d="M3.5 20a5.5 5.5 0 0 1 11 0" /><line x1="19" y1="9" x2="19" y2="15" /><line x1="16" y1="12" x2="22" y2="12" />',
  "new-group":
    '<circle cx="8.5" cy="9" r="3" /><path d="M3.5 19a5 5 0 0 1 10 0" /><path d="M15.5 7a3 3 0 0 1 0 5.6" /><path d="M16 14a5 5 0 0 1 4.5 5" />',
  "join-group":
    '<path d="M14 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3" /><path d="M10 8l4 4-4 4" /><line x1="14" y1="12" x2="4" y2="12" />',
  chat: '<path d="M21 11.5a8.5 8.5 0 0 1-12.3 7.6L3 21l1.9-5.6A8.5 8.5 0 1 1 21 11.5Z" />',
  fediverse:
    '<circle cx="12" cy="5" r="2.5" /><circle cx="6" cy="17" r="2.5" /><circle cx="18" cy="17" r="2.5" /><path d="M11 7.2 7.2 14.9" /><path d="M13 7.2l3.8 7.7" /><path d="M8.5 17h7" />',
  image:
    '<rect x="3" y="4" width="18" height="16" rx="2" /><circle cx="8.5" cy="9.5" r="1.8" /><path d="m4 17 4.5-4.5 3.5 3.5 3-3L21 17" />',
  back: '<path d="M19 12H5" /><path d="m12 19-7-7 7-7" />',
  bookmark: '<path d="M7 3h10a1 1 0 0 1 1 1v17l-6-4-6 4V4a1 1 0 0 1 1-1Z" />',
  share:
    '<circle cx="6" cy="12" r="2.5" /><circle cx="17" cy="6" r="2.5" /><circle cx="17" cy="18" r="2.5" /><path d="m8.2 10.9 6.6-3.8" /><path d="m8.2 13.1 6.6 3.8" />',
  chevron: '<path d="m9 6 6 6-6 6" />',
};

/// Build a live `<svg>` for `name`. Decorative by default
/// (`aria-hidden`); pass `label` when the icon is the only content of
/// an interactive control so assistive tech announces it.
export function icon(name: IconName, opts: { label?: string } = {}): SVGSVGElement {
  const markup =
    `<svg class="icon icon--${name}" viewBox="0 0 24 24" width="24" height="24"` +
    ` fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"` +
    ` stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg">${BODY[name]}</svg>`;
  const doc = new DOMParser().parseFromString(markup, "image/svg+xml");
  const svg = doc.documentElement as unknown as SVGSVGElement;
  if (opts.label) {
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", opts.label);
  } else {
    svg.setAttribute("aria-hidden", "true");
  }
  return svg;
}
