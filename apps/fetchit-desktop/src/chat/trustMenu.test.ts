import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mountTrustMenu } from "./trustMenu";
import type { Contact } from "./types";

const PEER = "b".repeat(64);

let host: HTMLElement;

beforeEach(() => {
  host = document.createElement("div");
  document.body.appendChild(host);
});

afterEach(() => {
  host.remove();
  vi.restoreAllMocks();
});

function contact(over: Partial<Contact> = {}): Contact {
  return {
    agent_id: PEER,
    trust_level: "unknown",
    label: "Bob",
    ...over,
  };
}

describe("mountTrustMenu", () => {
  it("preselects the contact's current trust level", () => {
    mountTrustMenu(host, contact({ trust_level: "trusted" }), {
      onSetTrust: () => {},
      onRemove: () => {},
    });
    const select = host.querySelector<HTMLSelectElement>(".chat-trust__select")!;
    expect(select.value).toBe("trusted");
    expect(select.options.length).toBe(4);
  });

  it("emits onSetTrust when the select changes", () => {
    const onSetTrust = vi.fn();
    mountTrustMenu(host, contact(), { onSetTrust, onRemove: () => {} });
    const select = host.querySelector<HTMLSelectElement>(".chat-trust__select")!;
    select.value = "trusted";
    select.dispatchEvent(new Event("change"));
    expect(onSetTrust).toHaveBeenCalledWith("trusted");
  });

  it("confirms before firing onRemove", async () => {
    // window.confirm is async in Tauri 2 — return a resolved promise.
    vi.spyOn(window, "confirm").mockReturnValue(
      Promise.resolve(true) as unknown as boolean,
    );
    const onRemove = vi.fn();
    mountTrustMenu(host, contact(), { onSetTrust: () => {}, onRemove });
    host.querySelector<HTMLButtonElement>(".chat-trust__remove")!.click();
    await new Promise((r) => setTimeout(r, 0));
    await new Promise((r) => setTimeout(r, 0));
    expect(onRemove).toHaveBeenCalledTimes(1);
  });

  it("does not call onRemove if the confirm is declined", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(
      Promise.resolve(false) as unknown as boolean,
    );
    const onRemove = vi.fn();
    mountTrustMenu(host, contact(), { onSetTrust: () => {}, onRemove });
    host.querySelector<HTMLButtonElement>(".chat-trust__remove")!.click();
    await new Promise((r) => setTimeout(r, 0));
    await new Promise((r) => setTimeout(r, 0));
    expect(onRemove).not.toHaveBeenCalled();
  });
});
