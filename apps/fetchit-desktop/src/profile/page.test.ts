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

const GALLERY = [
  { kind: "etchit", label: "showcase", addr: "d".repeat(64) },
  { kind: "fetchit", label: "city", addr: "e".repeat(64) },
  { kind: "website", label: "site", addr: "https://x.io" },
];

it("renders hex-kind links as gallery cards and opens them in the reader", () => {
  const opened: string[] = [];
  const root = document.createElement("div");
  renderProfilePage(model({ links: GALLERY }), root, { ...H, onAutonomi: (u) => opened.push(u) }, stubAvatar);
  const cards = root.querySelectorAll(".profile-page__etch");
  expect(cards).toHaveLength(2); // website excluded from the grid
  (cards[0] as HTMLElement).click();
  expect(opened[0]).toBe(`autonomi://${"d".repeat(64)}`);
});

it("website + unknown link kinds render as chips, not gallery cards", () => {
  const root = document.createElement("div");
  renderProfilePage(model({ links: GALLERY }), root, H, stubAvatar);
  expect(root.querySelectorAll(".profile-page__chip")).toHaveLength(1);
});

it("gallery fires zero fetches on render", () => {
  let calls = 0;
  const root = document.createElement("div");
  renderProfilePage(model({ links: GALLERY }), root, H, async () => { calls++; return ""; });
  expect(calls).toBe(0); // no avatar in this model, no link prefetch
});

it("own empty page shows the trinity handoff, both actions", () => {
  let edit = 0, get = 0;
  const root = document.createElement("div");
  renderProfilePage(model({ state: "none", verified: false, isSelf: true }), root,
    { ...H, onEditEtch: () => edit++, onGetEtch: () => get++ }, stubAvatar);
  expect(root.querySelector(".profile-page__handoff")).not.toBeNull();
  (root.querySelector("[data-act=create-etch]") as HTMLElement).click();
  (root.querySelector("[data-act=get-etch]") as HTMLElement).click();
  expect(edit).toBe(1);
  expect(get).toBe(1);
});

it("contact empty page is neutral, no etch/it advertising", () => {
  const root = document.createElement("div");
  renderProfilePage(model({ state: "none", verified: false, isSelf: false }), root, H, stubAvatar);
  expect(root.querySelector(".profile-page__handoff")).toBeNull();
  expect(root.querySelector(".profile-page__empty")?.textContent).toContain("hasn't published");
});

it("Share button present when shareUri is set", () => {
  const root = document.createElement("div");
  renderProfilePage(model({ shareUri: "fetchit://share/v3/aaa/bbb?relay=r" }), root, H, stubAvatar);
  expect(root.querySelector("[data-act=share]")).not.toBeNull();
});

it("Share button absent when shareUri is null", () => {
  const root = document.createElement("div");
  renderProfilePage(model({ shareUri: null }), root, H, stubAvatar);
  expect(root.querySelector("[data-act=share]")).toBeNull();
});
