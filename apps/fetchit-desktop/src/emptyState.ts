/// Public demo-city index address — the front door we share in
/// announcements. Sourced from fetchit-demo-city/addresses.txt
/// (INDEX slot). Surfaced as a one-click "try the demo city" CTA on
/// the empty-tab landing so a first-time user can fetch something
/// before knowing any address.
export const DEMO_CITY_INDEX =
  "ba9a8fcae5677af1876de8b37b1f728446754b6fe78307c2355be28cec94e764";

/// Render the empty-tab landing: a primary CTA that calls `onDemo`
/// plus a secondary hint pointing at the address bar.
export function buildEmptyState(onDemo: () => void): HTMLElement {
  const e = document.createElement("div");
  e.className = "tab-empty";

  const cta = document.createElement("button");
  cta.type = "button";
  cta.className = "tab-empty-cta";
  cta.dataset.testid = "empty-demo-cta";
  cta.textContent = "try the demo city";
  cta.addEventListener("click", onDemo);

  const hint = document.createElement("p");
  hint.className = "tab-empty-hint";
  hint.textContent = "or paste an autonomi address above";

  e.append(cta, hint);
  return e;
}
