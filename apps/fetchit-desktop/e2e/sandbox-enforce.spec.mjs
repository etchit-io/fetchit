// fetch>it desktop E2E — rendered-content sandbox ENFORCEMENT.
//
// fetch-render.spec.mjs checks the iframe sandbox attribute is SET. This
// spec proves the boundary actually DENIES: it renders a hostile fixture
// (src-tauri/src/e2e.rs HOSTILE_ADDR) whose inline script probes each
// escape vector from inside the rendered iframe and writes "blocked" /
// "LEAK" into per-probe divs. A "LEAK" on any probe is a real sandbox
// escape — this is the test that would fail if the rewriter, the CSP, or
// the iframe sandbox attribute regressed.

import { closeAllTabs } from "./helpers.mjs";

// Mirrors src-tauri/src/e2e.rs.
const HOSTILE_ADDR =
  "0000000000000000000000000000000000000000000000000000000000000005";

// Each probe div id -> what a "blocked" result proves was denied.
const SYNC_PROBES = {
  "p-tauri": "Tauri IPC bridge is unreachable from untrusted content",
  "p-rtc": "RTCPeerConnection neutered (no local-IP / data-channel leak)",
  "p-geo": "navigator.geolocation neutered",
  "p-beacon": "navigator.sendBeacon neutered (no connect-src bypass)",
  "p-sw": "navigator.serviceWorker neutered",
  "p-storage": "DOM storage denied by the null-origin sandbox",
  "p-relock": "a neutered global cannot be restored by the SPA",
  "p-parent": "the host frame is opaque to the null-origin iframe",
  "p-popup": "window.open denied (no allow-popups)",
};

async function fetchAddress(addr) {
  await $("#addr").setValue(addr);
  await $("#go").click();
}

describe("rendered-content sandbox enforcement", () => {
  beforeEach(closeAllTabs);

  it("denies every escape vector from inside the rendered iframe", async () => {
    await fetchAddress(HOSTILE_ADDR);
    const frame = $("#stage .tab-content .rendered-html iframe");
    await expect(frame).toBeExisting();
    // Re-assert the load-bearing attribute here too, so a single spec
    // failure pins the regression whether it's the attribute or the
    // runtime behaviour that broke.
    await expect(frame).toHaveAttribute("sandbox", "allow-scripts allow-forms");

    await browser.switchFrame(frame);
    try {
      // The probe script runs synchronously at parse time; expect()
      // auto-waits, so a slow load still converges. A "LEAK" (or the
      // unrun "x" placeholder) fails the assertion.
      for (const [id, proves] of Object.entries(SYNC_PROBES)) {
        await expect($(`#${id}`)).toHaveText("blocked", {
          message: `sandbox LEAK on #${id}: ${proves}`,
        });
      }

      // Egress is async (a rejected cross-origin fetch). Wait for the
      // probe to resolve out of its "pending" placeholder, then assert.
      await browser.waitUntil(
        async () => (await $("#p-fetch").getText()) !== "pending",
        {
          timeout: 15_000,
          timeoutMsg: "egress probe never resolved (fetch neither blocked nor leaked)",
        },
      );
      await expect($("#p-fetch")).toHaveText("blocked", {
        message:
          "sandbox LEAK on #p-fetch: CSP connect-src let a non-allowlisted origin through",
      });
    } finally {
      await browser.switchFrame(null);
    }
  });
});
