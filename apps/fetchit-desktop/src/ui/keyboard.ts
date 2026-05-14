import { invoke } from "@tauri-apps/api/core";
import type { TabStore } from "../tabs";

export function bindKeyboard(store: TabStore, onNew: () => void): void {
  document.addEventListener("keydown", (e) => {
    // F12: open devtools — available in dev and release (tauri's `devtools`
    // feature is enabled), so contributors and power users can inspect what
    // the WebView is doing.
    if (e.key === "F12") {
      e.preventDefault();
      void invoke("open_devtools").catch(() => {});
      return;
    }

    const mod = e.metaKey || e.ctrlKey;
    if (!mod) return;

    // Ctrl/Cmd + Shift + I → devtools (matches the browser convention).
    if (e.shiftKey && (e.key === "I" || e.key === "i")) {
      e.preventDefault();
      void invoke("open_devtools").catch(() => {});
      return;
    }

    if (e.key === "t" || e.key === "T") {
      e.preventDefault();
      onNew();
      return;
    }
    if (e.key === "w" || e.key === "W") {
      e.preventDefault();
      const a = store.active();
      if (a) store.close(a.id);
      return;
    }
    if (e.key === "Tab") {
      e.preventDefault();
      if (e.shiftKey) store.prev();
      else store.next();
      return;
    }
    if (e.key >= "1" && e.key <= "9") {
      e.preventDefault();
      store.at(Number.parseInt(e.key, 10) - 1);
    }
  });
}
