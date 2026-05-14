import { parseAutonomiInput } from "../address";

export interface AddressBarHooks {
  onSubmit: (addr: string) => void;
  onInvalid: (msg: string) => void;
}

export interface AddressBarApi {
  setValue: (v: string) => void;
  focus: () => void;
  clear: () => void;
  isFocused: () => boolean;
}

export function mountAddressBar(
  input: HTMLInputElement,
  button: HTMLButtonElement,
  hooks: AddressBarHooks,
): AddressBarApi {
  const submit = (): void => {
    const a = parseAutonomiInput(input.value);
    if (!a) {
      hooks.onInvalid("address must be 64 hex characters");
      return;
    }
    input.value = a;
    hooks.onSubmit(a);
  };
  button.addEventListener("click", submit);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") submit();
  });
  return {
    setValue: (v) => {
      input.value = v;
    },
    focus: () => {
      input.focus();
      input.select();
    },
    clear: () => {
      input.value = "";
      input.focus();
    },
    isFocused: () => document.activeElement === input,
  };
}
