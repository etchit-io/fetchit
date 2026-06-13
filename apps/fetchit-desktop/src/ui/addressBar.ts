import { parseAddressInput, type AddressInput } from "../address";

export interface AddressBarHooks {
  onSubmit: (address: string, query: string) => void;
  onProfile: (input: AddressInput) => void;
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
    const parsed = parseAddressInput(input.value);
    if (!parsed) {
      hooks.onInvalid("enter a 64-hex address or an @handle@domain");
      return;
    }
    if (parsed.kind === "hex") {
      input.value = parsed.address + parsed.query;
      hooks.onSubmit(parsed.address, parsed.query);
      return;
    }
    hooks.onProfile(parsed);
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
