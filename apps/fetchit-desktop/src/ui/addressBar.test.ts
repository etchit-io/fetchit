import { afterEach, describe, expect, it, vi } from "vitest";
import { mountAddressBar, type AddressBarApi } from "./addressBar";

const HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

function setup(): {
  input: HTMLInputElement;
  button: HTMLButtonElement;
  onSubmit: ReturnType<typeof vi.fn>;
  onProfile: ReturnType<typeof vi.fn>;
  onInvalid: ReturnType<typeof vi.fn>;
  api: AddressBarApi;
} {
  document.body.replaceChildren();
  const input = document.createElement("input");
  const button = document.createElement("button");
  document.body.appendChild(input);
  document.body.appendChild(button);
  const onSubmit = vi.fn();
  const onProfile = vi.fn();
  const onInvalid = vi.fn();
  const api = mountAddressBar(input, button, { onSubmit, onProfile, onInvalid });
  return { input, button, onSubmit, onProfile, onInvalid, api };
}

afterEach(() => {
  document.body.replaceChildren();
});

describe("mountAddressBar submit paths", () => {
  it("fires onSubmit with parsed address and empty query on Go-button click", () => {
    const { input, button, onSubmit, onInvalid } = setup();
    input.value = HEX;
    button.click();
    expect(onSubmit).toHaveBeenCalledTimes(1);
    expect(onSubmit).toHaveBeenCalledWith(HEX, "");
    expect(onInvalid).not.toHaveBeenCalled();
  });

  it("fires onSubmit on Enter keydown in the input", () => {
    const { input, onSubmit, onInvalid } = setup();
    input.value = HEX;
    input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter" }));
    expect(onSubmit).toHaveBeenCalledTimes(1);
    expect(onSubmit).toHaveBeenCalledWith(HEX, "");
    expect(onInvalid).not.toHaveBeenCalled();
  });

  it("ignores non-Enter keys", () => {
    const { input, onSubmit, onInvalid } = setup();
    input.value = HEX;
    for (const key of ["a", "ArrowDown", "ArrowUp", "Escape", " ", "Tab"]) {
      input.dispatchEvent(new KeyboardEvent("keydown", { key }));
    }
    expect(onSubmit).not.toHaveBeenCalled();
    expect(onInvalid).not.toHaveBeenCalled();
  });

  it("calls onInvalid with the error message for non-hex input", () => {
    const { input, button, onSubmit, onInvalid } = setup();
    input.value = "not-an-address";
    button.click();
    expect(onSubmit).not.toHaveBeenCalled();
    expect(onInvalid).toHaveBeenCalledTimes(1);
    expect(onInvalid).toHaveBeenCalledWith("enter a 64-hex address or an @handle@domain");
  });

  it("calls onInvalid for too-short hex input", () => {
    const { input, button, onSubmit, onInvalid } = setup();
    input.value = HEX.slice(0, 63);
    button.click();
    expect(onSubmit).not.toHaveBeenCalled();
    expect(onInvalid).toHaveBeenCalledWith("enter a 64-hex address or an @handle@domain");
  });

  it("strips an autonomi:// prefix and canonicalises the input value", () => {
    const { input, button, onSubmit, onInvalid } = setup();
    input.value = `autonomi://${HEX}`;
    button.click();
    expect(onSubmit).toHaveBeenCalledWith(HEX, "");
    expect(onInvalid).not.toHaveBeenCalled();
    expect(input.value).toBe(HEX);
  });

  it("preserves a query string and passes it separately to onSubmit", () => {
    const { input, button, onSubmit, onInvalid } = setup();
    input.value = `${HEX}?foo=bar`;
    button.click();
    expect(onSubmit).toHaveBeenCalledWith(HEX, "?foo=bar");
    expect(onInvalid).not.toHaveBeenCalled();
    expect(input.value).toBe(`${HEX}?foo=bar`);
  });

  it("rejects empty and whitespace-only input", () => {
    const { input, button, onSubmit, onInvalid } = setup();
    input.value = "";
    button.click();
    input.value = "   ";
    button.click();
    expect(onSubmit).not.toHaveBeenCalled();
    expect(onInvalid).toHaveBeenCalledTimes(2);
    expect(onInvalid).toHaveBeenCalledWith("enter a 64-hex address or an @handle@domain");
  });
});

describe("mountAddressBar api", () => {
  it("setValue writes to input.value without firing hooks", () => {
    const { input, api, onSubmit, onInvalid } = setup();
    api.setValue(HEX);
    expect(input.value).toBe(HEX);
    expect(onSubmit).not.toHaveBeenCalled();
    expect(onInvalid).not.toHaveBeenCalled();
  });

  it("clear empties input.value and focuses the input", () => {
    const { input, api, onSubmit, onInvalid } = setup();
    input.value = "leftover";
    api.clear();
    expect(input.value).toBe("");
    expect(document.activeElement).toBe(input);
    expect(onSubmit).not.toHaveBeenCalled();
    expect(onInvalid).not.toHaveBeenCalled();
  });

  it("focus() makes the input the active element and isFocused() reflects state", () => {
    const { input, api } = setup();
    expect(api.isFocused()).toBe(false);
    api.focus();
    expect(document.activeElement).toBe(input);
    expect(api.isFocused()).toBe(true);
  });
});
