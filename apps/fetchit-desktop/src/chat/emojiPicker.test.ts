import { describe, expect, it } from "vitest";
import { EMOJI, createEmojiPicker } from "./emojiPicker";

describe("emojiPicker", () => {
  it("exposes a non-empty, de-duplicated emoji set", () => {
    expect(EMOJI.length).toBeGreaterThan(0);
    expect(new Set(EMOJI).size).toBe(EMOJI.length);
  });

  it("renders one labelled button per emoji", () => {
    const picker = createEmojiPicker(() => {});
    const cells = picker.querySelectorAll<HTMLButtonElement>(
      "button.chat-emoji-picker__cell",
    );
    expect(cells.length).toBe(EMOJI.length);
    expect(cells[0].textContent).toBe(EMOJI[0]);
    expect(cells[0].getAttribute("aria-label")).toBe(EMOJI[0]);
  });

  it("calls onPick with the clicked emoji", () => {
    const picked: string[] = [];
    const picker = createEmojiPicker((e) => picked.push(e));
    const cells = picker.querySelectorAll<HTMLButtonElement>(
      "button.chat-emoji-picker__cell",
    );
    cells[3].click();
    expect(picked).toEqual([EMOJI[3]]);
  });

  it("labels the grid as a listbox", () => {
    const picker = createEmojiPicker(() => {});
    expect(picker.getAttribute("role")).toBe("listbox");
    expect(picker.getAttribute("aria-label")).toBe("Emoji");
  });
});
