// fetch>it desktop E2E — settings panel.
// Opening, rendering and closing the settings panel; no network.

import { closeSettings } from "./helpers.mjs";

describe("settings panel", () => {
  // Each test starts with the panel closed.
  beforeEach(closeSettings);

  it("opens from the gear button", async () => {
    await expect($("#settings")).not.toBeDisplayed();

    await $("#settings-toggle").click();

    await expect($("#settings")).toBeDisplayed();
    await expect($("#settings .settings-head h1")).toHaveText("Settings");
  });

  it("renders its sections when open", async () => {
    await $("#settings-toggle").click();
    await expect($("#settings")).toBeDisplayed();

    // Everyday sections are visible as soon as the panel opens.
    for (const id of ["#group-bookmarks", "#group-about"]) {
      await expect($(id)).toBeDisplayed();
    }

    // Power sections live inside the collapsed Advanced block and only
    // render once it is expanded (the panel's grandma-proofing default).
    const advanced = $("#group-advanced");
    await expect(advanced).toBeExisting();
    await advanced.$("summary").click();
    for (const id of ["#group-network", "#group-peers", "#group-cache"]) {
      await expect($(id)).toBeDisplayed();
    }
  });

  it("closes from the × button", async () => {
    await $("#settings-toggle").click();
    await expect($("#settings")).toBeDisplayed();

    await $(".settings-close").click();
    await expect($("#settings")).not.toBeDisplayed();
  });
});
