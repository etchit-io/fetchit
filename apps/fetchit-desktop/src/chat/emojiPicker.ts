// A compact emoji picker for the composer: a flat grid of common
// emoji where clicking a cell calls back with the character. No
// categories, search, or network -- a curated everyday set. The
// composer owns placement and open/close.

/// The curated emoji set. Iterated by the picker and the test-suite.
export const EMOJI = [
  "😀", "😂", "🙂", "😉", "😍", "😘", "😎", "🤔", "😅", "😭",
  "😡", "👍", "👎", "👏", "🙏", "💪", "🔥", "✨", "🎉", "❤️",
  "💔", "💯", "✅", "❌", "⚠️", "👀", "🙌", "🤝", "🤷", "🫡",
  "😬", "😴", "🤯", "🥳", "😇", "🙃", "😤", "🫶", "👋", "🤞",
  "🚀", "⭐", "💡", "📌", "🔒", "🔑", "⏳", "💬",
] as const;

/// Build a flat emoji grid. Clicking a cell calls `onPick` with that
/// emoji. Class hooks only; the composer styles + toggles it.
export function createEmojiPicker(onPick: (emoji: string) => void): HTMLElement {
  const grid = document.createElement("div");
  grid.className = "chat-emoji-picker";
  grid.setAttribute("role", "listbox");
  grid.setAttribute("aria-label", "Emoji");
  for (const emoji of EMOJI) {
    const cell = document.createElement("button");
    cell.type = "button";
    cell.className = "chat-emoji-picker__cell";
    cell.textContent = emoji;
    cell.setAttribute("aria-label", emoji);
    cell.addEventListener("click", () => onPick(emoji));
    grid.appendChild(cell);
  }
  return grid;
}
