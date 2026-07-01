// fetch>it desktop E2E — display-name persistence.
// The full chat surface depends on a live x0xd, which the `e2e`
// backend feature doesn't stub. This spec exercises only the
// settings-layer commands that back the display-name field, so
// it runs without any chat daemon present.

const invokeCmd = (cmd, args = {}) =>
  browser.executeAsync(
    async (cmd, args, done) => {
      try {
        // Tauri 2 exposes `invoke` via window.__TAURI__ when the
        // build sets `withGlobalTauri = true`. Fall back to the
        // internals API if it isn't.
        const t = window.__TAURI__?.core ?? window.__TAURI_INTERNALS__;
        const result = await t.invoke(cmd, args);
        done({ ok: true, result });
      } catch (e) {
        done({ ok: false, error: String(e) });
      }
    },
    cmd,
    args,
  );

describe("display name (settings command)", () => {
  // Reset before and after — leave no state behind for other specs.
  beforeEach(async () => {
    const r = await invokeCmd("set_display_name", { name: "" });
    if (!r.ok) throw new Error(`reset failed: ${r.error}`);
  });

  after(async () => {
    await invokeCmd("set_display_name", { name: "" });
  });

  it("starts empty when nothing has been persisted", async () => {
    const r = await invokeCmd("display_name");
    expect(r.ok).toBe(true);
    expect(r.result).toBe("");
  });

  it("round-trips through the settings store", async () => {
    const set = await invokeCmd("set_display_name", { name: "Alice 👋" });
    expect(set.ok).toBe(true);
    const got = await invokeCmd("display_name");
    expect(got.ok).toBe(true);
    expect(got.result).toBe("Alice 👋");
  });

  it("trims surrounding whitespace on set", async () => {
    await invokeCmd("set_display_name", { name: "  bob  " });
    const got = await invokeCmd("display_name");
    expect(got.result).toBe("bob");
  });

  it("empty/whitespace clears the field", async () => {
    await invokeCmd("set_display_name", { name: "Alice" });
    await invokeCmd("set_display_name", { name: "   " });
    const got = await invokeCmd("display_name");
    expect(got.result).toBe("");
  });
});
