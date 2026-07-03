import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

// eslint-disable-next-line import/first
import { invoke } from "@tauri-apps/api/core";
// eslint-disable-next-line import/first
import {
  LINK_OFFER_PREFIX,
  isLinkOfferUri,
  mountLinkDeviceModal,
} from "./linkDevice";

type InvokeMock = ReturnType<typeof vi.fn>;

const VALID_URI = `${LINK_OFFER_PREFIX}abc123payload`;
const SHORT_CODE = "ALPHA7";

function mount(): ReturnType<typeof mountLinkDeviceModal> {
  const host = document.createElement("section");
  document.body.appendChild(host);
  return mountLinkDeviceModal(host);
}

beforeEach(() => {
  (invoke as InvokeMock).mockReset();
  document.body.innerHTML = "";
});

describe("isLinkOfferUri", () => {
  it("accepts a fetchit://link/v1/ URI", () => {
    expect(isLinkOfferUri(`${LINK_OFFER_PREFIX}some-payload`)).toBe(true);
  });

  it("rejects an autonomi:// address", () => {
    expect(isLinkOfferUri(`autonomi://${"0".repeat(64)}`)).toBe(false);
  });

  it("rejects an https URL", () => {
    expect(isLinkOfferUri("https://example.com")).toBe(false);
  });

  it("rejects junk input", () => {
    expect(isLinkOfferUri("not a link")).toBe(false);
    expect(isLinkOfferUri("")).toBe(false);
  });

  it("trims whitespace before checking", () => {
    expect(isLinkOfferUri(`  ${LINK_OFFER_PREFIX}abc  `)).toBe(true);
  });
});

describe("mountLinkDeviceModal", () => {
  describe("modal mechanics", () => {
    it("starts hidden and tracks open/close", () => {
      const api = mount();
      expect(api.isOpen()).toBe(false);
      api.open();
      expect(api.isOpen()).toBe(true);
      api.close();
      expect(api.isOpen()).toBe(false);
    });
  });

  describe("existing device flow", () => {
    it("starts with preview and linked panels hidden", () => {
      const api = mount();
      api.open();
      const host = document.querySelector("section")!;
      expect(host.querySelector<HTMLElement>(".link-device-preview")!.hidden).toBe(true);
      expect(host.querySelector<HTMLElement>(".link-device-linked")!.hidden).toBe(true);
    });

    it("idle -> preview: shows the code on valid URI paste", async () => {
      (invoke as InvokeMock).mockResolvedValue({
        agentIdHex: "deadbeef",
        shortCode: SHORT_CODE,
        expired: false,
      });
      const api = mount();
      api.open();
      const host = document.querySelector("section")!;
      const input = host.querySelector<HTMLTextAreaElement>(".link-device-uri-input")!;
      input.value = VALID_URI;
      input.dispatchEvent(new Event("input"));
      await vi.waitFor(() => {
        expect(host.querySelector<HTMLElement>(".link-device-preview")!.hidden).toBe(false);
        expect(host.querySelector(".link-device-code--existing")!.textContent).toBe(SHORT_CODE);
      });
      expect(invoke).toHaveBeenCalledWith("chat_preview_link_offer", { uri: VALID_URI });
    });

    it("preview -> linked: enrolls on confirm click", async () => {
      (invoke as InvokeMock)
        .mockResolvedValueOnce({
          agentIdHex: "deadbeef",
          shortCode: SHORT_CODE,
          expired: false,
        })
        .mockResolvedValueOnce({
          agentIdHex: "deadbeef",
          recordRevision: 1,
          devicesGroupAdmitted: false,
        });
      const api = mount();
      api.open();
      const host = document.querySelector("section")!;
      const input = host.querySelector<HTMLTextAreaElement>(".link-device-uri-input")!;
      input.value = VALID_URI;
      input.dispatchEvent(new Event("input"));
      await vi.waitFor(() =>
        expect(host.querySelector<HTMLElement>(".link-device-preview")!.hidden).toBe(false),
      );
      host.querySelector<HTMLButtonElement>(".link-device-confirm-btn")!.click();
      await vi.waitFor(() => {
        expect(host.querySelector<HTMLElement>(".link-device-linked")!.hidden).toBe(false);
      });
      expect(invoke).toHaveBeenCalledWith("chat_enroll_confirmed_device", { uri: VALID_URI });
    });

    it("error path: preview fetch fails, status shows error", async () => {
      (invoke as InvokeMock).mockRejectedValue("relay unavailable");
      const api = mount();
      api.open();
      const host = document.querySelector("section")!;
      const input = host.querySelector<HTMLTextAreaElement>(".link-device-uri-input")!;
      input.value = VALID_URI;
      input.dispatchEvent(new Event("input"));
      await vi.waitFor(() => {
        const status = host.querySelector<HTMLElement>(".link-device-status")!;
        expect(status.textContent).toContain("relay unavailable");
        expect(status.hasAttribute("data-error")).toBe(true);
      });
      expect(host.querySelector<HTMLElement>(".link-device-preview")!.hidden).toBe(true);
    });

    it("error path: enroll fails, confirm button is re-enabled for retry", async () => {
      (invoke as InvokeMock)
        .mockResolvedValueOnce({
          agentIdHex: "deadbeef",
          shortCode: SHORT_CODE,
          expired: false,
        })
        .mockRejectedValueOnce("signing failed");
      const api = mount();
      api.open();
      const host = document.querySelector("section")!;
      const input = host.querySelector<HTMLTextAreaElement>(".link-device-uri-input")!;
      input.value = VALID_URI;
      input.dispatchEvent(new Event("input"));
      await vi.waitFor(() =>
        expect(host.querySelector<HTMLElement>(".link-device-preview")!.hidden).toBe(false),
      );
      host.querySelector<HTMLButtonElement>(".link-device-confirm-btn")!.click();
      await vi.waitFor(() => {
        const status = host.querySelector<HTMLElement>(".link-device-status")!;
        expect(status.textContent).toContain("signing failed");
        expect(status.hasAttribute("data-error")).toBe(true);
      });
      expect(
        host.querySelector<HTMLButtonElement>(".link-device-confirm-btn")!.disabled,
      ).toBe(false);
    });

    it("expired link: shows expiry message without revealing preview", async () => {
      (invoke as InvokeMock).mockResolvedValue({
        agentIdHex: "deadbeef",
        shortCode: SHORT_CODE,
        expired: true,
      });
      const api = mount();
      api.open();
      const host = document.querySelector("section")!;
      const input = host.querySelector<HTMLTextAreaElement>(".link-device-uri-input")!;
      input.value = VALID_URI;
      input.dispatchEvent(new Event("input"));
      await vi.waitFor(() => {
        const status = host.querySelector<HTMLElement>(".link-device-status")!;
        expect(status.textContent).toContain("expired");
        expect(status.hasAttribute("data-error")).toBe(true);
      });
      expect(host.querySelector<HTMLElement>(".link-device-preview")!.hidden).toBe(true);
    });

    it("invalid URI: sets error status without calling invoke", () => {
      const api = mount();
      api.open();
      const host = document.querySelector("section")!;
      const input = host.querySelector<HTMLTextAreaElement>(".link-device-uri-input")!;
      input.value = "https://example.com/not-a-link";
      input.dispatchEvent(new Event("input"));
      const status = host.querySelector<HTMLElement>(".link-device-status")!;
      expect(status.textContent).toBeTruthy();
      expect(status.hasAttribute("data-error")).toBe(true);
      expect(invoke).not.toHaveBeenCalled();
    });
  });

  describe("new device flow", () => {
    it("renders a QR SVG and shows the short code after generate", async () => {
      (invoke as InvokeMock).mockResolvedValue({
        uri: VALID_URI,
        shortCode: SHORT_CODE,
        expMs: Date.now() + 600_000,
      });
      const api = mount();
      api.open();
      const host = document.querySelector("section")!;
      host.querySelector<HTMLButtonElement>(".link-device-generate-btn")!.click();
      await vi.waitFor(() => {
        expect(host.querySelector<HTMLElement>(".link-device-new-active")!.hidden).toBe(false);
      });
      expect(invoke).toHaveBeenCalledWith("chat_create_link_offer", { ttlSecs: 600 });
      expect(host.querySelector(".link-device-qr-slot svg")).not.toBeNull();
      expect(host.querySelector(".link-device-code--new")!.textContent).toBe(SHORT_CODE);
    });

    it("error path: create fails, re-enables the button", async () => {
      (invoke as InvokeMock).mockRejectedValue("network error");
      const api = mount();
      api.open();
      const host = document.querySelector("section")!;
      const btn = host.querySelector<HTMLButtonElement>(".link-device-generate-btn")!;
      btn.click();
      await vi.waitFor(() => {
        const err = host.querySelector<HTMLElement>(".link-device-new-error")!;
        expect(err.hidden).toBe(false);
        expect(err.textContent).toContain("network error");
      });
      expect(btn.disabled).toBe(false);
    });
  });
});
