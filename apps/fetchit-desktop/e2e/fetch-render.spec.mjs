// fetch>it desktop E2E — fetch and render.
// Submits fixture addresses (served by the `e2e`-feature backend stub)
// and asserts each content type reaches the matching renderer.

import { closeAllTabs } from "./helpers.mjs";

// Fixture addresses — mirror src-tauri/src/e2e.rs.
const TEXT_ADDR = "0000000000000000000000000000000000000000000000000000000000000001";
const JSON_ADDR = "0000000000000000000000000000000000000000000000000000000000000002";
const HTML_ADDR = "0000000000000000000000000000000000000000000000000000000000000003";
const UNKNOWN_ADDR = "00000000000000000000000000000000000000000000000000000000000000ff";

async function fetchAddress(addr) {
  await $("#addr").setValue(addr);
  await $("#go").click();
}

describe("fetch and render", () => {
  beforeEach(closeAllTabs);

  it("renders a text fixture", async () => {
    await fetchAddress(TEXT_ADDR);
    const pre = $("#stage .tab-content pre.code-block");
    await expect(pre).toBeDisplayed();
    await expect(pre).toHaveText("E2E text fixture", { containing: true });
  });

  it("renders a JSON fixture", async () => {
    await fetchAddress(JSON_ADDR);
    const pre = $("#stage .tab-content pre");
    await expect(pre).toBeDisplayed();
    await expect(pre).toHaveText("count", { containing: true });
  });

  it("renders an HTML fixture in a sandboxed iframe", async () => {
    await fetchAddress(HTML_ADDR);
    const frame = $("#stage .tab-content .rendered-html iframe");
    await expect(frame).toBeExisting();
    await expect(frame).toHaveAttribute("sandbox", "allow-scripts allow-forms");
  });

  it("shows the error state when the fetch has no content", async () => {
    await fetchAddress(UNKNOWN_ADDR);
    await expect($("#stage .tab-content .tab-error")).toBeDisplayed();
    await expect($("#stage .tab-content .tab-error-heading")).toHaveText(
      "fetch failed",
    );
  });
});
