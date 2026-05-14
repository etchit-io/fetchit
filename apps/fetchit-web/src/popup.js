// Popup is intentionally inert — no IPC, no telemetry, no clipboard reads.
// Only thing it does dynamically is stamp the manifest version into the
// footer so a release bump doesn't require touching popup.html.

const manifest = chrome.runtime.getManifest?.();
const verEl = document.getElementById("ver");
if (verEl && manifest?.version) verEl.textContent = manifest.version;
