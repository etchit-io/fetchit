import { it, expect } from "vitest";
import { renderProfilePage, type ProfilePageHandlers } from "./page";
import type { ProfilePageModel } from "./open";

const noop = () => {};
const H: ProfilePageHandlers = {
  onAutonomi: noop, onMessage: noop, onInvite: noop, onShare: noop,
  onEditEtch: noop, onGetEtch: noop, confirmOpen: noop,
};
const stubAvatar = async () => "data:image/webp;base64,AA==";
function model(over: Partial<ProfilePageModel>): ProfilePageModel {
  return { state: "verified", agentId: "a".repeat(64), handle: "@josh@etchit.io",
    display: "Josh", verified: true, changedHands: false, verifyFailure: null,
    bio: "hi", website: null, avatar: null, links: [], shareUri: "fetchit://share/v3/x", isSelf: false, error: null, ...over };
}

it("verified page shows the badge, name, and private actions", () => {
  const root = document.createElement("div");
  renderProfilePage(model({}), root, H, stubAvatar);
  expect(root.querySelector(".profile-page__badge")).not.toBeNull();
  expect(root.querySelector(".profile-page__name")?.textContent).toBe("Josh");
  expect(root.querySelector("[data-act=message]")).not.toBeNull();
  expect(root.querySelector("[data-act=invite]")).not.toBeNull();
});

it("public-only page hides private actions and shows the failure", () => {
  const root = document.createElement("div");
  renderProfilePage(model({ state: "publicOnly", verified: false, verifyFailure: "bad sig" }), root, H, stubAvatar);
  expect(root.querySelector(".profile-page__badge")).toBeNull();
  expect(root.querySelector("[data-act=message]")).toBeNull();
  expect(root.querySelector(".profile-page__verify-fail")?.textContent).toContain("bad sig");
});

it("changed-hands renders the warning band", () => {
  const root = document.createElement("div");
  renderProfilePage(model({ changedHands: true }), root, H, stubAvatar);
  expect(root.querySelector(".profile-page__changed")).not.toBeNull();
});

it("error state renders an honest card, no trust affordances", () => {
  const root = document.createElement("div");
  renderProfilePage(model({ state: "error", error: "network down", verified: false }), root, H, stubAvatar);
  expect(root.querySelector(".profile-page__error")?.textContent).toContain("network down");
  expect(root.querySelector("[data-act=message]")).toBeNull();
});

it("escapes untrusted display fields (textContent, never innerHTML)", () => {
  const root = document.createElement("div");
  renderProfilePage(model({ display: "<img src=x onerror=alert(1)>" }), root, H, stubAvatar);
  expect(root.querySelector("img")).toBeNull();
});
