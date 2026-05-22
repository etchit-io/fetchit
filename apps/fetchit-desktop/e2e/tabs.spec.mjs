// fetch>it desktop E2E — tab strip.
// Opening, switching and closing tabs; no network.

import { closeAllTabs } from "./helpers.mjs";

const NEW_TAB = "#tabs .tab-new";

// mountTabStrip re-renders the whole strip on every change, so an element
// handle taken before a click goes stale — always re-query through tabs().
const tabs = () => $$("#tabs .tab");

describe("tab strip", () => {
  beforeEach(closeAllTabs);

  it("opens a tab from the new-tab control", async () => {
    await expect($("#tabs")).toHaveAttribute("data-empty", "true");
    await expect($(NEW_TAB)).toHaveText("new tab +");
    await expect(tabs()).toBeElementsArrayOfSize(0);

    await $(NEW_TAB).click();

    await expect($("#tabs")).toHaveAttribute("data-empty", "false");
    await expect(tabs()).toBeElementsArrayOfSize(1);
    await expect($("#tabs .tab")).toHaveAttribute("aria-selected", "true");
    await expect($("#tabs .tab .tab-label")).toHaveText("new tab");
    // With a tab open the control collapses to a bare "+".
    await expect($(NEW_TAB)).toHaveText("+");
  });

  it("switches between open tabs", async () => {
    await $(NEW_TAB).click();
    await $(NEW_TAB).click();
    await expect(tabs()).toBeElementsArrayOfSize(2);

    // createEmpty activates the newest tab.
    await expect((await tabs())[1]).toHaveAttribute("aria-selected", "true");
    await expect((await tabs())[0]).toHaveAttribute("aria-selected", "false");

    await (await $$("#tabs .tab .tab-label"))[0].click();
    await expect((await tabs())[0]).toHaveAttribute("aria-selected", "true");
    await expect((await tabs())[1]).toHaveAttribute("aria-selected", "false");
  });

  it("closes tabs back to the empty state", async () => {
    await $(NEW_TAB).click();
    await $(NEW_TAB).click();
    await expect(tabs()).toBeElementsArrayOfSize(2);

    await (await $$("#tabs .tab-close"))[0].click();
    await expect(tabs()).toBeElementsArrayOfSize(1);

    await (await $$("#tabs .tab-close"))[0].click();
    await expect(tabs()).toBeElementsArrayOfSize(0);
    await expect($("#tabs")).toHaveAttribute("data-empty", "true");
  });
});
