// Shared helpers for the fetch>it desktop E2E specs.

// Close every open tab, leaving the empty tab strip.
export async function closeAllTabs() {
  for (let guard = 0; guard < 20; guard += 1) {
    const closers = await $$("#tabs .tab-close");
    if (closers.length === 0) break;
    await closers[0].click();
  }
}

// Close the settings panel if it is open.
export async function closeSettings() {
  if (await $("#settings").isDisplayed()) {
    await $(".settings-close").click();
  }
}
