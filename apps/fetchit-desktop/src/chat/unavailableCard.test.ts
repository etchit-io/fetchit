import { describe, expect, it } from "vitest";
import {
  CHAT_UNAVAILABLE_COPY,
  classifyBootstrapError,
  renderChatUnavailableCard,
} from "./unavailableCard";

describe("classifyBootstrapError", () => {
  it("treats keyring failures as keystore problems", () => {
    expect(classifyBootstrapError(new Error("keyring get: no secret service"))).toBe("keystore");
    expect(classifyBootstrapError("keyring open: dbus down")).toBe("keystore");
  });

  it("treats everything else as transient", () => {
    expect(classifyBootstrapError(new Error("connect refused 127.0.0.1:45000"))).toBe("transient");
    expect(classifyBootstrapError(undefined)).toBe("transient");
  });
});

describe("renderChatUnavailableCard", () => {
  it("renders the keystore copy with the Settings pointer", () => {
    const host = document.createElement("div");
    renderChatUnavailableCard(host, "keystore");
    expect(host.querySelector(".chat-unavailable")).not.toBeNull();
    expect(host.textContent).toContain(CHAT_UNAVAILABLE_COPY.keystore);
    expect(host.textContent).toContain("Settings");
  });

  it("renders the transient copy and replaces a prior card", () => {
    const host = document.createElement("div");
    renderChatUnavailableCard(host, "keystore");
    renderChatUnavailableCard(host, "transient");
    expect(host.querySelectorAll(".chat-unavailable").length).toBe(1);
    expect(host.textContent).toContain(CHAT_UNAVAILABLE_COPY.transient);
    expect(host.textContent).not.toContain("Settings > Advanced");
  });
});
