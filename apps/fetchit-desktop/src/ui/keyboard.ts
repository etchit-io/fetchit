import { invoke } from "@tauri-apps/api/core";
import type { TabStore } from "../tabs";

export interface KeyboardActions {
  newTab: () => void;
  refresh: () => void;
  back: () => void;
  focusAddress: () => void;
  blurFocused: () => void;
  smartPaste: () => void;
  smartCopy: () => void;
  openSettings: () => void;
  openShare: () => void;
  toggleBookmark: () => void;
}

function isEditableTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.tagName === "INPUT" || target.tagName === "TEXTAREA") return true;
  return target.isContentEditable;
}

export function bindKeyboard(store: TabStore, actions: KeyboardActions): void {
  document.addEventListener("keydown", (e) => {
    // ----- modifier-less keys -----

    // F12 → devtools (dev + release; tauri's `devtools` feature is on).
    if (e.key === "F12") {
      e.preventDefault();
      void invoke("open_devtools").catch(() => {});
      return;
    }

    // F5 → refresh. preventDefault so the WebView shell never reloads the
    // whole app (which would lose every tab).
    if (e.key === "F5") {
      e.preventDefault();
      actions.refresh();
      return;
    }

    // Esc → blur whatever is focused (gets you out of the address bar).
    if (e.key === "Escape") {
      actions.blurFocused();
      return;
    }

    // Alt + ← → back in the active tab's history (browser convention).
    if (e.altKey && e.key === "ArrowLeft") {
      e.preventDefault();
      actions.back();
      return;
    }

    // ----- modifier-bearing keys -----
    const mod = e.metaKey || e.ctrlKey;
    if (!mod) return;

    // Ctrl/Cmd + Shift + I → devtools.
    if (e.shiftKey && (e.key === "I" || e.key === "i")) {
      e.preventDefault();
      void invoke("open_devtools").catch(() => {});
      return;
    }

    // Ctrl/Cmd + Shift + S → share QR for the active address.
    if (e.shiftKey && (e.key === "S" || e.key === "s")) {
      e.preventDefault();
      actions.openShare();
      return;
    }

    // Ctrl/Cmd + R → refresh.
    if (e.key === "r" || e.key === "R") {
      e.preventDefault();
      actions.refresh();
      return;
    }

    // Ctrl/Cmd + L → focus address bar (browser convention).
    if (e.key === "l" || e.key === "L") {
      e.preventDefault();
      actions.focusAddress();
      return;
    }

    // Ctrl/Cmd + , → open settings (browser / macOS convention).
    if (e.key === ",") {
      e.preventDefault();
      actions.openSettings();
      return;
    }

    // Ctrl/Cmd + D → bookmark / unbookmark the active tab (browser convention).
    if (e.key === "d" || e.key === "D") {
      e.preventDefault();
      actions.toggleBookmark();
      return;
    }

    // Ctrl/Cmd + V → smart paste: if focus is anywhere outside an
    // editable element, read the clipboard and submit if it parses as
    // an Autonomi address. Inside inputs we let the native paste run.
    if (!e.shiftKey && (e.key === "v" || e.key === "V")) {
      if (!isEditableTarget(e.target)) {
        e.preventDefault();
        actions.smartPaste();
      }
      return;
    }

    // Ctrl/Cmd + C → smart copy: if focus is anywhere outside an
    // editable element AND there's nothing selected, copy the active
    // tab's address to the clipboard. Otherwise let the native copy run
    // so explicit text selection still works.
    if (!e.shiftKey && (e.key === "c" || e.key === "C")) {
      const hasSelection = !!window.getSelection()?.toString();
      if (!isEditableTarget(e.target) && !hasSelection) {
        e.preventDefault();
        actions.smartCopy();
      }
      return;
    }

    if (e.key === "t" || e.key === "T") {
      e.preventDefault();
      actions.newTab();
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
