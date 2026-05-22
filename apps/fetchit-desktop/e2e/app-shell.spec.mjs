// fetch>it desktop E2E — app-shell flows that need no network.
// Cold launch and address-bar input validation, driven through
// tauri-driver against the real Tauri app.

describe("app shell", () => {
  it("cold-launches the reader chrome", async () => {
    await expect(browser).toHaveTitle("fetchit");

    await expect($("#addr")).toBeDisplayed();
    await expect($("#addr")).toHaveAttribute("placeholder", "Autonomi address");
    await expect($("#go")).toHaveText("fetch");
    await expect($("#mark")).toBeDisplayed();

    // No history on a fresh launch — back stays disabled.
    await expect($("#back-toggle")).toBeDisabled();
    // No documents open — the tab strip reports empty.
    await expect($("#tabs")).toHaveAttribute("data-empty", "true");
  });

  it("rejects a non-hex address without starting a fetch", async () => {
    await $("#addr").setValue("not-a-real-autonomi-address");
    await $("#go").click();

    // mountAddressBar → onInvalid → the message lands in #status.
    await expect($("#status")).toHaveText("address must be 64 hex characters");
    // Invalid input opens no tab and shows no fetch spinner.
    await expect($("#tabs")).toHaveAttribute("data-empty", "true");
    await expect($(".tab-spinner")).not.toBeExisting();
  });
});
