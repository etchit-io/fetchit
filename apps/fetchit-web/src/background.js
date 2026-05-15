// fetch>it background service worker. Three jobs:
//   1. Right-click "Open in fetch>it" on any text selection containing a
//      64-hex Autonomi address.
//   2. Omnibox keyword `fetchit <address>` — quick navigation from the URL
//      bar without first finding a link.
//   3. Action-click fallback — when the user clicks the toolbar icon on a
//      page with an active autonomi:// selection, open it directly.
//
// The extension does not run any network code. It just routes addresses
// to the OS scheme handler (fetch>it desktop), which performs the actual
// Autonomi fetch and renders the result.

import { parseAutonomiInput } from "./addr.js";

const MENU_ID = "fetchit-open-selection";

function openAutonomi(addr, options = {}) {
  if (!addr) return;
  const url = `autonomi://${addr}`;
  const newTab = options.newTab === true;
  if (newTab) {
    chrome.tabs.create({ url }).catch(() => {});
  } else if (typeof options.tabId === "number") {
    chrome.tabs.update(options.tabId, { url }).catch(() => {});
  } else {
    chrome.tabs.update({ url }).catch(() => {});
  }
}

// onInstalled fires once when the extension is installed/updated/reloaded.
// Registering the menu every load would duplicate it; doing it here is the
// MV3-canonical place.
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: MENU_ID,
    title: "Open in fetch>it",
    contexts: ["selection"],
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId !== MENU_ID) return;
  const addr = parseAutonomiInput(info.selectionText || "");
  if (!addr) return;
  openAutonomi(addr, { tabId: tab?.id });
});

// Omnibox: user types `fetchit ` in the URL bar, then an address. We never
// suggest results from the user's history — only echo the address back, so
// no inadvertent data goes anywhere.
chrome.omnibox.setDefaultSuggestion?.({
  description: "Type a 64-hex Autonomi address to open in fetch>it",
});

chrome.omnibox.onInputChanged?.addListener((text, suggest) => {
  const addr = parseAutonomiInput(text);
  suggest(
    addr
      ? [{ content: addr, description: `Open ${addr.slice(0, 12)}… in fetch>it` }]
      : [],
  );
});

chrome.omnibox.onInputEntered.addListener((text, disposition) => {
  const addr = parseAutonomiInput(text);
  if (!addr) return;
  openAutonomi(addr, { newTab: disposition === "newForegroundTab" || disposition === "newBackgroundTab" });
});
