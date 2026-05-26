import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const isPermGrantedMock = vi.fn<() => Promise<boolean>>();
const requestPermMock = vi.fn<() => Promise<NotificationPermission>>();
const sendNotifMock = vi.fn();

vi.mock("@tauri-apps/plugin-notification", () => ({
  isPermissionGranted: () => isPermGrantedMock(),
  requestPermission: () => requestPermMock(),
  sendNotification: (o: unknown) => sendNotifMock(o),
}));

import { ChatStore } from "./state";
import { _resetNotifyState, maybeNotifyInboundDm } from "./notify";

const ME = "a".repeat(64);
const PEER = "b".repeat(64);

let store: ChatStore;

beforeEach(() => {
  localStorage.clear();
  _resetNotifyState();
  isPermGrantedMock.mockReset();
  requestPermMock.mockReset();
  sendNotifMock.mockReset();
  store = new ChatStore();
  store.setIdentity({ agent_id: ME, machine_id: "m" });
  vi.spyOn(document, "hasFocus").mockReturnValue(false);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("maybeNotifyInboundDm", () => {
  it("notifies for inbound DMs when permission is already granted", async () => {
    isPermGrantedMock.mockResolvedValue(true);
    await maybeNotifyInboundDm(store, {
      from: PEER, to: ME, body: "hello there",
      sender_name: "Bob", timestamp_ms: 1, message_id: "m1",
    });
    expect(sendNotifMock).toHaveBeenCalledTimes(1);
    expect(sendNotifMock.mock.calls[0][0]).toMatchObject({
      title: "fetch>it · DM",
      body: "Bob: hello there",
    });
  });

  it("skips when the message is mine (echo)", async () => {
    isPermGrantedMock.mockResolvedValue(true);
    await maybeNotifyInboundDm(store, {
      from: ME, to: PEER, body: "yo", timestamp_ms: 1, message_id: "m1",
    });
    expect(sendNotifMock).not.toHaveBeenCalled();
  });

  it("skips when the window has focus", async () => {
    vi.spyOn(document, "hasFocus").mockReturnValue(true);
    isPermGrantedMock.mockResolvedValue(true);
    await maybeNotifyInboundDm(store, {
      from: PEER, to: ME, body: "hi", timestamp_ms: 1, message_id: "m1",
    });
    expect(sendNotifMock).not.toHaveBeenCalled();
  });

  it("requests permission when default and respects a denial", async () => {
    isPermGrantedMock.mockResolvedValue(false);
    requestPermMock.mockResolvedValue("denied");
    await maybeNotifyInboundDm(store, {
      from: PEER, to: ME, body: "knock", timestamp_ms: 1, message_id: "m1",
    });
    expect(sendNotifMock).not.toHaveBeenCalled();
    // second message: should not re-prompt
    await maybeNotifyInboundDm(store, {
      from: PEER, to: ME, body: "knock 2", timestamp_ms: 2, message_id: "m2",
    });
    expect(requestPermMock).toHaveBeenCalledTimes(1);
  });

  it("falls back to a truncated contact label when sender_name is absent", async () => {
    isPermGrantedMock.mockResolvedValue(true);
    store.loadContacts([
      { agent_id: PEER, trust_level: "trusted", label: "Bob" },
    ]);
    await maybeNotifyInboundDm(store, {
      from: PEER, to: ME, body: "no name", timestamp_ms: 1, message_id: "m1",
    });
    expect(sendNotifMock.mock.calls[0][0]).toMatchObject({
      body: "Bob: no name",
    });
  });

  it("truncates body at 140 characters", async () => {
    isPermGrantedMock.mockResolvedValue(true);
    const long = "x".repeat(500);
    await maybeNotifyInboundDm(store, {
      from: PEER, to: ME, body: long,
      sender_name: "Bob", timestamp_ms: 1, message_id: "m1",
    });
    const call = sendNotifMock.mock.calls[0][0] as { body: string };
    expect(call.body.length).toBeLessThanOrEqual(5 /*"Bob: "*/ + 140);
    expect(call.body.endsWith("…")).toBe(true);
  });

  it("skips empty bodies", async () => {
    isPermGrantedMock.mockResolvedValue(true);
    await maybeNotifyInboundDm(store, {
      from: PEER, to: ME, body: "   ", timestamp_ms: 1, message_id: "m1",
    });
    expect(sendNotifMock).not.toHaveBeenCalled();
  });
});
