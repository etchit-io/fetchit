import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(() => Promise.resolve()),
}));

import { invoke } from "@tauri-apps/api/core";
import { startIdleTracker, type IdleTracker } from "./idle";

const MIN = 60 * 1000;

describe("startIdleTracker", () => {
  let tracker: IdleTracker;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.mocked(invoke).mockReset();
    vi.mocked(invoke).mockResolvedValue(undefined);
    tracker = startIdleTracker();
  });

  afterEach(() => {
    tracker.destroy();
    vi.useRealTimers();
  });

  it("does not fire when timeout is zero", () => {
    tracker.setTimeoutMinutes(0);
    vi.advanceTimersByTime(24 * 60 * MIN);
    expect(invoke).not.toHaveBeenCalled();
  });

  it("fires idle_disconnect after the configured minutes", () => {
    tracker.setTimeoutMinutes(5);
    vi.advanceTimersByTime(5 * MIN);
    expect(invoke).toHaveBeenCalledTimes(1);
    expect(invoke).toHaveBeenCalledWith("idle_disconnect");
  });

  it("does not fire even one ms before the deadline", () => {
    tracker.setTimeoutMinutes(5);
    vi.advanceTimersByTime(5 * MIN - 1);
    expect(invoke).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(invoke).toHaveBeenCalledTimes(1);
  });

  it("user activity resets the timer", () => {
    tracker.setTimeoutMinutes(5);
    vi.advanceTimersByTime(4 * MIN);
    document.dispatchEvent(new Event("mousemove"));
    vi.advanceTimersByTime(4 * MIN);
    expect(invoke).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1 * MIN);
    expect(invoke).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["mousemove"],
    ["keydown"],
    ["wheel"],
    ["touchstart"],
    ["click"],
  ])("activity event %s resets the pending timer", (name) => {
    tracker.setTimeoutMinutes(5);
    vi.advanceTimersByTime(4 * MIN);
    document.dispatchEvent(new Event(name));
    vi.advanceTimersByTime(5 * MIN - 1);
    expect(invoke).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(invoke).toHaveBeenCalledTimes(1);
  });

  it("manual bump() resets the timer", () => {
    tracker.setTimeoutMinutes(5);
    vi.advanceTimersByTime(4 * MIN);
    tracker.bump();
    vi.advanceTimersByTime(4 * MIN);
    expect(invoke).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1 * MIN);
    expect(invoke).toHaveBeenCalledTimes(1);
  });

  it("setTimeoutMinutes updates and restarts the timer", () => {
    tracker.setTimeoutMinutes(5);
    vi.advanceTimersByTime(2 * MIN);
    tracker.setTimeoutMinutes(10);
    vi.advanceTimersByTime(5 * MIN);
    expect(invoke).not.toHaveBeenCalled();
    vi.advanceTimersByTime(5 * MIN);
    expect(invoke).toHaveBeenCalledTimes(1);
  });

  it("setTimeoutMinutes(-3) is clamped to 0 and never fires", () => {
    tracker.setTimeoutMinutes(-3);
    vi.advanceTimersByTime(24 * 60 * MIN);
    expect(invoke).not.toHaveBeenCalled();
  });

  it("setTimeoutMinutes(2.9) floors to 2 minutes", () => {
    tracker.setTimeoutMinutes(2.9);
    vi.advanceTimersByTime(2 * MIN - 1);
    expect(invoke).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(invoke).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(1 * MIN);
    expect(invoke).toHaveBeenCalledTimes(1);
  });

  it("destroy() removes listeners and cancels the pending timer", () => {
    tracker.setTimeoutMinutes(5);
    tracker.destroy();
    document.dispatchEvent(new Event("mousemove"));
    vi.advanceTimersByTime(60 * MIN);
    expect(invoke).not.toHaveBeenCalled();
  });

  it("idle_disconnect rejection is swallowed without unhandled rejection", async () => {
    vi.mocked(invoke).mockRejectedValueOnce(new Error("backend gone"));
    const onUnhandled = vi.fn();
    process.on("unhandledRejection", onUnhandled);
    try {
      tracker.setTimeoutMinutes(5);
      vi.advanceTimersByTime(5 * MIN);
      expect(invoke).toHaveBeenCalledTimes(1);
      await vi.runAllTimersAsync();
      await Promise.resolve();
      expect(onUnhandled).not.toHaveBeenCalled();
    } finally {
      process.off("unhandledRejection", onUnhandled);
    }
  });
});
