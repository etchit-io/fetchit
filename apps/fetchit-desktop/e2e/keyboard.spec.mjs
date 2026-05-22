// fetch>it desktop E2E — keyboard shortcuts.
// Tab and settings shortcuts; no network.

import { closeAllTabs, closeSettings } from "./helpers.mjs";

describe("keyboard shortcuts", () => {
  beforeEach(async () => {
    await closeAllTabs();
    await closeSettings();
  });

  it("opens a tab with Ctrl/Cmd+T", async () => {
    await expect($$("#tabs .tab")).toBeElementsArrayOfSize(0);
    await browser.keys(["Control", "t"]);
    await expect($$("#tabs .tab")).toBeElementsArrayOfSize(1);
  });

  it("closes the active tab with Ctrl/Cmd+W", async () => {
    await browser.keys(["Control", "t"]);
    await expect($$("#tabs .tab")).toBeElementsArrayOfSize(1);
    await browser.keys(["Control", "w"]);
    await expect($$("#tabs .tab")).toBeElementsArrayOfSize(0);
  });

  it("opens settings with Ctrl/Cmd+, then closes it with Escape", async () => {
    await expect($("#settings")).not.toBeDisplayed();
    await browser.keys(["Control", ","]);
    await expect($("#settings")).toBeDisplayed();
    await browser.keys(["Escape"]);
    await expect($("#settings")).not.toBeDisplayed();
  });
});
