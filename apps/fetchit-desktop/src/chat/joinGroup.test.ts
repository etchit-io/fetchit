import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mountJoinGroup } from "./joinGroup";

const joinGroupMock =
  vi.fn<
    (invite: string, displayName?: string) =>
      Promise<{ group_id: string; name: string }>
  >();

vi.mock("./api", () => ({
  joinGroup: (invite: string, displayName?: string) =>
    joinGroupMock(invite, displayName),
}));

const VALID = "x0x://invite/abcdefghijklmnop";

let host: HTMLElement;

beforeEach(() => {
  joinGroupMock.mockReset();
  host = document.createElement("div");
  document.body.appendChild(host);
});

afterEach(() => {
  host.remove();
});

describe("mountJoinGroup", () => {
  it("disables the Join button until an invite URI is pasted", () => {
    mountJoinGroup(host, "me", { onClose: () => {}, onJoined: () => {} });
    const btn = host.querySelector<HTMLButtonElement>(".chat-dialog__btn")!;
    expect(btn.disabled).toBe(true);

    const input = host.querySelector<HTMLInputElement>(".chat-dialog__uri")!;
    input.value = "not-an-invite";
    input.dispatchEvent(new Event("input"));
    expect(btn.disabled).toBe(true);

    input.value = VALID;
    input.dispatchEvent(new Event("input"));
    expect(btn.disabled).toBe(false);
  });

  it("pre-fills the input when an initialUri is supplied", () => {
    mountJoinGroup(
      host,
      "me",
      { onClose: () => {}, onJoined: () => {} },
      VALID,
    );
    const input = host.querySelector<HTMLInputElement>(".chat-dialog__uri")!;
    const btn = host.querySelector<HTMLButtonElement>(".chat-dialog__btn")!;
    expect(input.value).toBe(VALID);
    expect(btn.disabled).toBe(false);
  });

  it("calls the API and onJoined on submit", async () => {
    joinGroupMock.mockResolvedValueOnce({ group_id: "g1", name: "fam" });
    const onJoined = vi.fn();
    mountJoinGroup(host, "me", { onClose: () => {}, onJoined }, VALID);
    const btn = host.querySelector<HTMLButtonElement>(".chat-dialog__btn")!;
    btn.click();
    await Promise.resolve();
    await Promise.resolve();
    expect(joinGroupMock).toHaveBeenCalledWith(VALID, "me");
    expect(onJoined).toHaveBeenCalledWith({ group_id: "g1", name: "fam" });
  });

  it("surfaces daemon errors in the status row and re-enables Join", async () => {
    joinGroupMock.mockRejectedValueOnce(new Error("bad invite"));
    mountJoinGroup(host, "me", { onClose: () => {}, onJoined: () => {} }, VALID);
    const btn = host.querySelector<HTMLButtonElement>(".chat-dialog__btn")!;
    btn.click();
    await Promise.resolve();
    await Promise.resolve();
    const status = host.querySelector<HTMLElement>(".chat-dialog__status")!;
    expect(status.textContent).toContain("bad invite");
    expect(btn.disabled).toBe(false);
  });
});
