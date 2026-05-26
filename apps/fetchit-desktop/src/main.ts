import { init } from "./controller";
import { applyTheme, loadTheme } from "./theme/theme";

// Apply the persisted theme before any UI mounts so the initial paint
// matches the user's last choice — no flash of the default theme.
applyTheme(loadTheme());

// Suppress the webview's default right-click context menu in release
// builds — in dev mode it's the only way to reach Inspect Element, so
// we leave it on. Text inputs / textareas / contenteditable always
// keep the native menu so paste / select-all stay reachable.
if (!import.meta.env.DEV) {
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
}

window.addEventListener("DOMContentLoaded", init);
