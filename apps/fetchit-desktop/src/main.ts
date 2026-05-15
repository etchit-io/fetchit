import { init } from "./controller";
import { applyTheme, loadTheme } from "./theme/theme";

// Apply the persisted theme before any UI mounts so the initial paint
// matches the user's last choice — no flash of the default theme.
applyTheme(loadTheme());

window.addEventListener("DOMContentLoaded", init);
