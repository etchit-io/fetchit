import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mountJoinGroup } from "./joinGroup";

const joinGroupMock =
  vi.fn<
    (invite: string, displayName?: string) =>
      Promise<
        | { status: "converged"; group: { group_id: string; name: string } }
        | { status: "pending"; group_id: string }
      >
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

    const input = host.querySelector<HTMLTextAreaElement>(".chat-dialog__uri")!;
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
    const input = host.querySelector<HTMLTextAreaElement>(".chat-dialog__uri")!;
    const btn = host.querySelector<HTMLButtonElement>(".chat-dialog__btn")!;
    expect(input.value).toBe(VALID);
    expect(btn.disabled).toBe(false);
  });

  it("calls the API and onJoined on a converged submit", async () => {
    joinGroupMock.mockResolvedValueOnce({
      status: "converged",
      group: { group_id: "g1", name: "fam" },
    });
    const onJoined = vi.fn();
    mountJoinGroup(host, "me", { onClose: () => {}, onJoined }, VALID);
    const btn = host.querySelector<HTMLButtonElement>(".chat-dialog__btn")!;
    btn.click();
    await Promise.resolve();
    await Promise.resolve();
    expect(joinGroupMock).toHaveBeenCalledWith(VALID, "me");
    expect(onJoined).toHaveBeenCalledWith({ group_id: "g1", name: "fam" });
  });

  it("treats a Pending outcome as joining, not a failure", async () => {
    joinGroupMock.mockResolvedValueOnce({ status: "pending", group_id: "g2" });
    const onJoined = vi.fn();
    const onPending = vi.fn();
    mountJoinGroup(
      host,
      "me",
      { onClose: () => {}, onJoined, onPending },
      VALID,
    );
    const btn = host.querySelector<HTMLButtonElement>(".chat-dialog__btn")!;
    btn.click();
    await Promise.resolve();
    await Promise.resolve();
    const status = host.querySelector<HTMLElement>(".chat-dialog__status")!;
    expect(status.textContent).toContain("Joining…");
    expect(onPending).toHaveBeenCalledWith("g2");
    expect(onJoined).not.toHaveBeenCalled();
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
