import { describe, expect, it } from "vitest";
import { connectionBannerCopy } from "./connectionBanner";

describe("connectionBannerCopy", () => {
  it("shows nothing when fully connected", () => {
    expect(connectionBannerCopy("connected", "connected")).toBeNull();
    expect(connectionBannerCopy(null, null)).toBeNull();
  });

  it("stays silent during first-boot relay connecting (not an outage)", () => {
    expect(connectionBannerCopy("connected", "connecting")).toBeNull();
    expect(connectionBannerCopy(null, "connecting")).toBeNull();
  });

  it("reassures (not alarms) when the relay link is down", () => {
    const copy = connectionBannerCopy("connected", "down");
    expect(copy?.tone).toBe("warn");
    expect(copy?.text).toContain("saved");
    expect(copy?.text).toContain("back online");
    // Never the old alarming close-and-reopen instruction.
    expect(copy?.text.toLowerCase()).not.toContain("reopen");
  });

  it("shows a calm reconnecting line for a transient relay blip", () => {
    const copy = connectionBannerCopy("connected", "reconnecting");
    expect(copy?.tone).toBe("info");
    expect(copy?.text.toLowerCase()).toContain("reconnecting");
  });

  it("lets the local chat service state win over the relay link", () => {
    // Daemon down is the deeper failure; its copy shows even if relay also down.
    const copy = connectionBannerCopy("down", "down");
    expect(copy?.tone).toBe("warn");
    expect(copy?.text.toLowerCase()).toContain("chat service");
    expect(copy?.text).toContain("saved");
  });

  it("shows a calm reconnecting line while the chat service comes back", () => {
    const copy = connectionBannerCopy("reconnecting", "connected");
    expect(copy?.tone).toBe("info");
    expect(copy?.text.toLowerCase()).toContain("reconnecting");
    expect(copy?.text).toContain("saved");
  });
});
