import type { Bookmark } from "../bookmarks";
import { listBookmarks } from "../bookmarks";

const MAX_RESULTS = 8;
const HEX_PREFIX = /^[0-9a-f]{8,}$/i;

/**
 * Filter bookmarks by case-insensitive substring match on the label.
 * Returns empty for empty queries and for hex-address-prefix queries
 * (≥ 8 pure-hex chars), so paste-an-address doesn't trigger the
 * dropdown.
 */
export function filterBookmarks(
  query: string,
  bookmarks: readonly Bookmark[],
  limit = MAX_RESULTS,
): Bookmark[] {
  const q = query.trim().toLowerCase();
  if (!q || HEX_PREFIX.test(q)) return [];
  return bookmarks
    .filter((b) => b.label.toLowerCase().includes(q))
    .slice(0, limit);
}

export interface SuggestionsHandle {
  refresh(): Promise<void>;
}

export interface MountOptions {
  input: HTMLInputElement;
  onSelect: (address: string) => void;
}

/**
 * Mount a bookmark-label typeahead beneath the address input. Call the
 * returned `refresh()` after bookmark mutations to keep the list in
 * sync. The dropdown is appended as a sibling of the input; the input's
 * parent must establish a positioning context for the absolute layout.
 */
export function mountAddressBarSuggestions(
  opts: MountOptions,
): SuggestionsHandle {
  const { input, onSelect } = opts;
  const parent = input.parentElement;
  if (!parent) throw new Error("address input has no parent");

  let bookmarks: Bookmark[] = [];
  let visible: Bookmark[] = [];
  let highlight = -1;

  const list = document.createElement("ul");
  list.className = "addr-suggestions";
  list.setAttribute("role", "listbox");
  list.hidden = true;
  parent.appendChild(list);

  const render = (): void => {
    list.replaceChildren();
    visible.forEach((b, i) => {
      const li = document.createElement("li");
      li.className = "addr-suggestion";
      if (i === highlight) li.classList.add("is-active");
      li.setAttribute("role", "option");

      const label = document.createElement("span");
      label.className = "addr-suggestion-label";
      label.textContent = b.label;

      const addr = document.createElement("span");
      addr.className = "addr-suggestion-address";
      addr.textContent = `${b.address.slice(0, 8)}…${b.address.slice(-4)}`;

      li.append(label, addr);
      // mousedown fires before the input.blur handler hides the list;
      // plain click would be lost to the blur-triggered hide.
      li.addEventListener("mousedown", (e) => {
        e.preventDefault();
        select(i);
      });
      list.appendChild(li);
    });
    list.hidden = visible.length === 0;
  };

  const select = (i: number): void => {
    const b = visible[i];
    if (!b) return;
    input.value = b.address;
    hide();
    onSelect(b.address);
  };

  const update = (): void => {
    visible = filterBookmarks(input.value, bookmarks);
    highlight = visible.length > 0 ? 0 : -1;
    render();
  };

  const hide = (): void => {
    visible = [];
    highlight = -1;
    list.hidden = true;
  };

  input.addEventListener("input", update);
  input.addEventListener("focus", update);
  input.addEventListener("blur", () => {
    // Delay so a pending mousedown selection fires before the hide.
    window.setTimeout(hide, 100);
  });
  // Capture phase + stopImmediatePropagation so a Enter pick lands here
  // before the address-bar module's own Enter-to-submit handler fires.
  input.addEventListener(
    "keydown",
    (e) => {
      if (list.hidden || visible.length === 0) return;
      if (e.key === "ArrowDown") {
        e.preventDefault();
        e.stopImmediatePropagation();
        highlight = (highlight + 1) % visible.length;
        render();
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        e.stopImmediatePropagation();
        highlight = (highlight - 1 + visible.length) % visible.length;
        render();
      } else if (e.key === "Enter" && highlight >= 0) {
        e.preventDefault();
        e.stopImmediatePropagation();
        select(highlight);
      } else if (e.key === "Escape") {
        e.preventDefault();
        e.stopImmediatePropagation();
        hide();
      }
    },
    { capture: true },
  );

  const refresh = async (): Promise<void> => {
    bookmarks = await listBookmarks().catch(() => []);
    if (document.activeElement === input) update();
  };
  void refresh();

  return { refresh };
}
