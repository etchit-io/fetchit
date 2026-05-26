import { init } from "./controller";
import { applyTheme, loadTheme } from "./theme/theme";

// Apply the persisted theme before any UI mounts so the initial paint
// matches the user's last choice — no flash of the default theme.
applyTheme(loadTheme());

// Suppress the webview's default right-click context menu (which in
// dev builds exposes "Inspect Element"). Keep it on text inputs and
// textareas so paste / select-all stay reachable.
window.addEventListener("contextmenu", (e) => {
  const t = e.target;
  if (
    t instanceof HTMLInputElement
    || t instanceof HTMLTextAreaElement
    || (t instanceof HTMLElement && t.isContentEditable)
  ) {
    return;
  }
  e.preventDefault();
});

window.addEventListener("DOMContentLoaded", init);
