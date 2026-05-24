/* eslint-disable @typescript-eslint/no-non-null-assertion */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { findMascotIn, mountMascot, type MascotController } from "./mascot";

describe("mascot", () => {
  let parent: HTMLElement;
  let controller: MascotController;

  beforeEach(() => {
    parent = document.createElement("div");
    document.body.appendChild(parent);
    controller = mountMascot();
    parent.appendChild(controller.element);
  });

  afterEach(() => {
    controller.dispose();
    parent.remove();
  });

  it("starts in the idle-running phase", () => {
    expect(controller.phase).toBe("idle-running");
    expect(controller.element.classList.contains("mascot--idle-running")).toBe(true);
  });

  it("renders an inline SVG scene with the puppy group", () => {
    const svg = controller.element.querySelector("svg.mascot-svg");
    expect(svg).not.toBeNull();
    expect(svg!.querySelector(".puppy")).not.toBeNull();
    expect(svg!.querySelector(".puppy-saddle")).not.toBeNull();
    expect(svg!.querySelector(".puppy-tongue")).not.toBeNull();
    expect(svg!.querySelector(".puppy-eye-highlight")).not.toBeNull();
    // Each leg has a nested `.puppy-leg-knee` group; the rotation
    // pair animates upper + lower independently.
    const legs = svg!.querySelectorAll(".puppy-leg");
    expect(legs.length).toBe(4);
    legs.forEach((leg) => {
      expect(leg.querySelector(".puppy-leg-knee")).not.toBeNull();
    });
  });

  it("transitions to resolving on a resolving-phase event", () => {
    controller.applyProgress({ address: "x", phase: "resolving", done: 0, total: 0 });
    expect(controller.phase).toBe("resolving");
    expect(controller.element.classList.contains("mascot--resolving")).toBe(true);
    expect(controller.element.classList.contains("mascot--idle-running")).toBe(false);
    expect(controller.element.querySelector(".mascot-label")?.textContent).toBe(
      "sniffing the trail…",
    );
  });

  it("transitions to fetching with a percentage label below 90%", () => {
    controller.applyProgress({ address: "x", phase: "fetching", done: 25, total: 100 });
    expect(controller.phase).toBe("fetching");
    expect(controller.element.classList.contains("mascot--fetching")).toBe(true);
    expect(controller.element.querySelector(".mascot-label")?.textContent).toBe(
      "fetching 25%",
    );
  });

  it("flips to sprinting once progress crosses 90%", () => {
    controller.applyProgress({ address: "x", phase: "fetching", done: 90, total: 100 });
    expect(controller.phase).toBe("sprinting");
    expect(controller.element.classList.contains("mascot--sprinting")).toBe(true);
    expect(controller.element.classList.contains("mascot--fetching")).toBe(false);
  });

  it("clamps overshooting progress percentages to 100", () => {
    controller.applyProgress({ address: "x", phase: "fetching", done: 200, total: 100 });
    expect(controller.element.querySelector(".mascot-label")?.textContent).toBe(
      "fetching 100%",
    );
  });

  it("reports 0% when total is not yet known", () => {
    controller.applyProgress({ address: "x", phase: "fetching", done: 0, total: 0 });
    expect(controller.element.querySelector(".mascot-label")?.textContent).toBe(
      "fetching 0%",
    );
  });

  it("can be re-applied through multiple phases without leaving stale classes", () => {
    controller.applyProgress({ address: "x", phase: "resolving", done: 0, total: 0 });
    controller.applyProgress({ address: "x", phase: "fetching", done: 30, total: 100 });
    controller.applyProgress({ address: "x", phase: "fetching", done: 95, total: 100 });
    const classes = controller.element.classList;
    expect(classes.contains("mascot--sprinting")).toBe(true);
    expect(classes.contains("mascot--fetching")).toBe(false);
    expect(classes.contains("mascot--resolving")).toBe(false);
    expect(classes.contains("mascot--idle-running")).toBe(false);
  });
});

describe("findMascotIn", () => {
  it("locates the live mascot mounted inside a container", () => {
    const parent = document.createElement("div");
    const m = mountMascot();
    parent.appendChild(m.element);
    expect(findMascotIn(parent)).toBe(m);
    m.dispose();
  });

  it("returns undefined for a container with no mascot", () => {
    const empty = document.createElement("div");
    expect(findMascotIn(empty)).toBeUndefined();
  });

  it("returns undefined after dispose removes the element", () => {
    const parent = document.createElement("div");
    const m = mountMascot();
    parent.appendChild(m.element);
    m.dispose();
    expect(findMascotIn(parent)).toBeUndefined();
  });
});

describe("dispose", () => {
  it("removes the element from the DOM", () => {
    const parent = document.createElement("div");
    document.body.appendChild(parent);
    const m = mountMascot();
    parent.appendChild(m.element);
    expect(parent.contains(m.element)).toBe(true);
    m.dispose();
    expect(parent.contains(m.element)).toBe(false);
    parent.remove();
  });

  it("is idempotent — calling twice does not throw", () => {
    const m = mountMascot();
    document.body.appendChild(m.element);
    m.dispose();
    expect(() => m.dispose()).not.toThrow();
  });
});
