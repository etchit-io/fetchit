import { describe, expect, it } from "vitest";
import { renderEncryptedEnvelope } from "./encryptedEnvelope";

describe("renderEncryptedEnvelope", () => {
  it("renders the card with group hint and ciphertext size", () => {
    const into = document.createElement("div");
    renderEncryptedEnvelope(
      { kind: "encryptedEnvelope", groupHint: "reading-club", ciphertextLen: 1088 },
      into,
    );
    expect(into.querySelector(".encrypted-notice")).not.toBeNull();
    expect(into.querySelector(".encrypted-notice__title")?.textContent).toBe(
      "Encrypted content",
    );
    expect(into.querySelector(".encrypted-notice__hint")?.textContent).toBe(
      "Group: reading-club",
    );
    expect(into.querySelector(".encrypted-notice__size")?.textContent).toContain(
      "1,088",
    );
  });

  it("omits the hint line when absent and never renders the hint as HTML", () => {
    const into = document.createElement("div");
    renderEncryptedEnvelope(
      { kind: "encryptedEnvelope", groupHint: null, ciphertextLen: 3 },
      into,
    );
    expect(into.querySelector(".encrypted-notice__hint")).toBeNull();

    const into2 = document.createElement("div");
    renderEncryptedEnvelope(
      {
        kind: "encryptedEnvelope",
        groupHint: "<img src=x onerror=alert(1)>",
        ciphertextLen: 3,
      },
      into2,
    );
    expect(into2.querySelector("img")).toBeNull();
  });
});
