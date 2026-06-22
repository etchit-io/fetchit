import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mountNewGroup } from "./newGroup";
import type { Group } from "./types";

type Preset = "private_secure" | "public_open";

const createGroupMock = vi.fn<
  (name: string, displayName: string | undefined, preset: Preset) =>
    Promise<Group>
>();
const groupInviteMock = vi.fn<(groupId: string) => Promise<string>>();

vi.mock("./api", () => ({
  createGroup: (name: string, displayName: string | undefined, preset: Preset) =>
    createGroupMock(name, displayName, preset),
  groupInvite: (groupId: string) => groupInviteMock(groupId),
}));

let host: HTMLElement;

beforeEach(() => {
  createGroupMock.mockReset();
  groupInviteMock.mockReset();
  host = document.createElement("div");
  document.body.appendChild(host);
});

afterEach(() => {
  host.remove();
});

function getCreateBtn(): HTMLButtonElement {
  const btns = host.querySelectorAll<HTMLButtonElement>(".chat-dialog__btn");
  for (const b of btns) {
    if (b.textContent === "Create") return b;
  }
  throw new Error("Create button not found");
}

function getNameInput(): HTMLInputElement {
  return host.querySelector<HTMLInputElement>(
    "input.chat-dialog__uri",
  )!;
}

function getRadios(): {
  privateRadio: HTMLInputElement;
  publicRadio: HTMLInputElement;
} {
  const all = host.querySelectorAll<HTMLInputElement>(
    'input[name="group-preset"]',
  );
  return {
    privateRadio: all[0],
    publicRadio: all[1],
  };
}

function getBtnByText(text: string): HTMLButtonElement {
  const btns = host.querySelectorAll<HTMLButtonElement>(".chat-dialog__btn");
  for (const b of btns) {
    if (b.textContent === text) return b;
  }
  throw new Error(`button "${text}" not found`);
}

function getInviteBox(): HTMLTextAreaElement {
  return host.querySelector<HTMLTextAreaElement>("textarea.chat-dialog__uri")!;
}

describe("mountNewGroup", () => {
  it("renders both preset radios with Private selected by default", () => {
    mountNewGroup(host, "Alice", { onClose: () => {}, onCreated: () => {} });
    const { privateRadio, publicRadio } = getRadios();
    expect(privateRadio.value).toBe("private_secure");
    expect(publicRadio.value).toBe("public_open");
    expect(privateRadio.checked).toBe(true);
    expect(publicRadio.checked).toBe(false);
  });

  it("calls createGroup with private_secure by default", async () => {
    createGroupMock.mockResolvedValueOnce({
      group_id: "g1",
      name: "fam",
    } as Group);
    groupInviteMock.mockResolvedValueOnce("x0x://invite/abc");
    const onCreated = vi.fn();
    mountNewGroup(host, "Alice", { onClose: () => {}, onCreated });

    const input = getNameInput();
    input.value = "fam";
    input.dispatchEvent(new Event("input"));

    getCreateBtn().click();
    await new Promise((r) => setTimeout(r, 0));

    expect(createGroupMock).toHaveBeenCalledWith("fam", "Alice", "private_secure");
    expect(onCreated).toHaveBeenCalledTimes(1);
  });

  it("calls createGroup with public_open when public radio selected", async () => {
    createGroupMock.mockResolvedValueOnce({
      group_id: "g2",
      name: "lounge",
    } as Group);
    groupInviteMock.mockResolvedValueOnce("x0x://invite/def");
    mountNewGroup(host, "Alice", { onClose: () => {}, onCreated: () => {} });

    const { publicRadio } = getRadios();
    publicRadio.checked = true;
    publicRadio.dispatchEvent(new Event("change"));

    const input = getNameInput();
    input.value = "lounge";
    input.dispatchEvent(new Event("input"));

    getCreateBtn().click();
    await new Promise((r) => setTimeout(r, 0));

    expect(createGroupMock).toHaveBeenCalledWith("lounge", "Alice", "public_open");
  });

  it("mints a fresh invite per invitee via the New invite button", async () => {
    createGroupMock.mockResolvedValueOnce({
      group_id: "g1",
      name: "fam",
    } as Group);
    groupInviteMock
      .mockResolvedValueOnce("x0x://invite/first")
      .mockResolvedValueOnce("x0x://invite/second");
    mountNewGroup(host, "Alice", { onClose: () => {}, onCreated: () => {} });

    const input = getNameInput();
    input.value = "fam";
    input.dispatchEvent(new Event("input"));
    getCreateBtn().click();
    await new Promise((r) => setTimeout(r, 0));

    // One invite minted on create, shown in the invite box.
    expect(groupInviteMock).toHaveBeenCalledTimes(1);
    expect(groupInviteMock).toHaveBeenLastCalledWith("g1");
    const box = getInviteBox();
    expect(box.value).toBe("x0x://invite/first");

    // "New invite" mints a FRESH single-use invite for the next person,
    // so the group can grow past two members (x0xd invites are single-use).
    const newInviteBtn = getBtnByText("New invite");
    expect(newInviteBtn.hidden).toBe(false);
    newInviteBtn.click();
    await new Promise((r) => setTimeout(r, 0));

    expect(groupInviteMock).toHaveBeenCalledTimes(2);
    expect(groupInviteMock).toHaveBeenLastCalledWith("g1");
    expect(box.value).toBe("x0x://invite/second");
  });
});
