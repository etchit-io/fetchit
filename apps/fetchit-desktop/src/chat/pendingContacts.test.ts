import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const confirmContactMock = vi.fn<(groupIdHex: string) => Promise<void>>();
const removeContactMock = vi.fn<(agentId: string) => Promise<void>>();

vi.mock("./api", () => ({
  confirmContact: (g: string) => confirmContactMock(g),
  removeContact: (a: string) => removeContactMock(a),
}));

import { mountPendingContactsDialog } from "./pendingContacts";
import { ChatStore } from "./state";

const PEER_A = "a".repeat(64);
const PEER_B = "b".repeat(64);

let host: HTMLElement;
let store: ChatStore;

beforeEach(() => {
  confirmContactMock.mockReset();
  removeContactMock.mockReset();
  host = document.createElement("div");
  document.body.appendChild(host);
  store = new ChatStore();
});

afterEach(() => {
  host.remove();
});

function getRows(): HTMLElement[] {
  return Array.from(host.querySelectorAll<HTMLElement>(".pending-contact-row"));
}

function getButtonsByLabel(row: HTMLElement): {
  accept: HTMLButtonElement;
  reject: HTMLButtonElement;
} {
  const btns = Array.from(row.querySelectorAll<HTMLButtonElement>("button"));
  const accept = btns.find((b) => b.textContent === "Accept")!;
  const reject = btns.find((b) => b.textContent === "Reject")!;
  return { accept, reject };
}

describe("mountPendingContactsDialog", () => {
  it("renders 'No pending requests' when the store is empty", () => {
    mountPendingContactsDialog(host, store, { onClose: () => {} });
    expect(host.textContent).toContain("No pending requests");
    expect(getRows()).toHaveLength(0);
  });

  it("renders one row per pending entry, newest first", () => {
    store.addPendingContact({
      groupIdHex: "g-old",
      peerAgentId: PEER_A,
      arrivedAtMs: 1,
    });
    store.addPendingContact({
      groupIdHex: "g-new",
      peerAgentId: PEER_B,
      arrivedAtMs: 100,
    });
    mountPendingContactsDialog(host, store, { onClose: () => {} });
    const rows = getRows();
    expect(rows).toHaveLength(2);
    expect(rows[0].dataset.groupId).toBe("g-new");
    expect(rows[1].dataset.groupId).toBe("g-old");
  });

  it("Accept invokes chat_confirm_contact with the group id and drops the row", async () => {
    confirmContactMock.mockResolvedValueOnce(undefined);
    store.addPendingContact({
      groupIdHex: "g1",
      peerAgentId: PEER_A,
      arrivedAtMs: 1,
    });
    mountPendingContactsDialog(host, store, { onClose: () => {} });
    const { accept } = getButtonsByLabel(getRows()[0]);
    accept.click();
    await Promise.resolve();
    await Promise.resolve();

    expect(confirmContactMock).toHaveBeenCalledWith("g1");
    expect(removeContactMock).not.toHaveBeenCalled();
    expect(store.allPendingContacts()).toHaveLength(0);
  });

  it("Reject invokes chat_remove_contact with the peer's agent id and drops the row", async () => {
    removeContactMock.mockResolvedValueOnce(undefined);
    store.addPendingContact({
      groupIdHex: "g1",
      peerAgentId: PEER_A,
      arrivedAtMs: 1,
    });
    mountPendingContactsDialog(host, store, { onClose: () => {} });
    const { reject } = getButtonsByLabel(getRows()[0]);
    reject.click();
    await Promise.resolve();
    await Promise.resolve();

    expect(removeContactMock).toHaveBeenCalledWith(PEER_A);
    expect(confirmContactMock).not.toHaveBeenCalled();
    expect(store.allPendingContacts()).toHaveLength(0);
  });

  it("re-enables buttons and surfaces the error if accept fails", async () => {
    confirmContactMock.mockRejectedValueOnce(new Error("relay offline"));
    store.addPendingContact({
      groupIdHex: "g1",
      peerAgentId: PEER_A,
      arrivedAtMs: 1,
    });
    mountPendingContactsDialog(host, store, { onClose: () => {} });
    const row = getRows()[0];
    const { accept, reject } = getButtonsByLabel(row);
    accept.click();
    await Promise.resolve();
    await Promise.resolve();

    expect(accept.disabled).toBe(false);
    expect(reject.disabled).toBe(false);
    expect(row.textContent).toContain("relay offline");
    // Entry MUST stay in the store so the user can retry without
    // re-receiving the welcome.
    expect(store.allPendingContacts()).toHaveLength(1);
  });

  it("redraws live when the store fires after mount", () => {
    mountPendingContactsDialog(host, store, { onClose: () => {} });
    expect(host.textContent).toContain("No pending requests");
    store.addPendingContact({
      groupIdHex: "g1",
      peerAgentId: PEER_A,
      arrivedAtMs: 1,
    });
    // The store emits subscribers synchronously on add.
    expect(getRows()).toHaveLength(1);
  });

  it("backdrop click closes; panel click does not", () => {
    const onClose = vi.fn();
    mountPendingContactsDialog(host, store, { onClose });
    host.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(onClose).toHaveBeenCalledTimes(1);

    const panel = host.querySelector<HTMLElement>(".chat-dialog__panel")!;
    panel.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
