// Theme tokens are declared in styles.css under `body[data-theme="..."]`.
// This module persists the user's choice across launches and applies it
// by setting `document.body.dataset.theme`.

export type Theme = "dark" | "dim" | "light";

export const THEMES: readonly Theme[] = ["dark", "dim", "light"] as const;

const STORAGE_KEY = "fetchit-theme";
const DEFAULT: Theme = "dark";

export function loadTheme(): Theme {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    return THEMES.includes(v as Theme) ? (v as Theme) : DEFAULT;
  } catch {
    return DEFAULT;
  }
}

export function applyTheme(theme: Theme): void {
  document.body.dataset.theme = theme;
  try {
    localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // localStorage may be unavailable (private mode, quota); applying the
    // attribute alone still themes the running window.
  }
}
