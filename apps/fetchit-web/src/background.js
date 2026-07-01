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

import { parseAutonomiUrl } from "./addr.js";

const MENU_ID = "fetchit-open-selection";

function openAutonomi(addr, options = {}) {
  if (!addr) return;
  const query = typeof options.query === "string" ? options.query : "";
  const url = `autonomi://${addr}${query}`;
  const newTab = options.newTab === true;
  const onErr = (e) => {
    // Surface to DevTools so issues are visible without firing a notification.
    // Common cause: the OS has no handler registered for autonomi:// — i.e.
    // fetch>it desktop isn't installed.
    console.warn("[fetch>it] failed to open", url, e);
  };
  try {
    if (newTab) {
      chrome.tabs.create({ url }, () => {
        if (chrome.runtime.lastError) onErr(chrome.runtime.lastError);
      });
    } else if (typeof options.tabId === "number") {
      chrome.tabs.update(options.tabId, { url }, () => {
        if (chrome.runtime.lastError) onErr(chrome.runtime.lastError);
      });
    } else {
      chrome.tabs.update({ url }, () => {
        if (chrome.runtime.lastError) onErr(chrome.runtime.lastError);
      });
    }
  } catch (e) {
    onErr(e);
  }
}

// (Re)create the context menu. Called from both onInstalled (install / update)
// and onStartup (browser launch with the extension already installed). We
// removeAll() first because re-creating with an existing id throws
// "Cannot create item with duplicate id" — happens on extension updates and
// in some Firefox restart paths.
function ensureContextMenu() {
  if (!chrome.contextMenus) return;
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create(
      {
        id: MENU_ID,
        title: "Open in fetch>it",
        contexts: ["selection"],
      },
      () => {
        if (chrome.runtime.lastError) {
          console.warn(
            "[fetch>it] contextMenus.create failed:",
            chrome.runtime.lastError.message,
          );
        }
      },
    );
  });
}

chrome.runtime.onInstalled.addListener(ensureContextMenu);
// onStartup fires when the browser launches and the extension is already
// installed. In MV3 the service worker can outlive a single browser session,
// but we don't rely on that — re-asserting the menu here is cheap.
chrome.runtime.onStartup?.addListener(ensureContextMenu);

chrome.contextMenus?.onClicked.addListener((info, tab) => {
  if (info.menuItemId !== MENU_ID) return;
  const parsed = parseAutonomiUrl(info.selectionText || "");
  if (!parsed) {
    console.warn(
      "[fetch>it] selection isn't a valid 64-hex Autonomi address:",
      info.selectionText,
    );
    return;
  }
  openAutonomi(parsed.address, { tabId: tab?.id, query: parsed.query });
});

// Omnibox: user types `fetchit ` in the URL bar, then an address. We never
// suggest results from the user's history — only echo the address back, so
// no inadvertent data goes anywhere. The whole omnibox API is optional —
// Safari ports don't expose it, so every call guards on its existence.
if (chrome.omnibox) {
  chrome.omnibox.setDefaultSuggestion?.({
    description: "Type a 64-hex Autonomi address to open in fetch>it",
  });

  chrome.omnibox.onInputChanged?.addListener((text, suggest) => {
    const parsed = parseAutonomiUrl(text);
    suggest(
      parsed
        ? [
            {
              content: parsed.address + parsed.query,
              description: `Open ${parsed.address.slice(0, 12)}… in fetch>it`,
            },
          ]
        : [],
    );
  });

  chrome.omnibox.onInputEntered?.addListener((text, disposition) => {
    const parsed = parseAutonomiUrl(text);
    if (!parsed) {
      console.warn(
        "[fetch>it] omnibox entry isn't a valid 64-hex Autonomi address:",
        text,
      );
      return;
    }
    openAutonomi(parsed.address, {
      query: parsed.query,
      newTab:
        disposition === "newForegroundTab" || disposition === "newBackgroundTab",
    });
  });
}
