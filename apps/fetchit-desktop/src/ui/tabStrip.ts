import type { Tab, TabStore } from "../tabs";

export function mountTabStrip(host: HTMLElement, store: TabStore, onNew: () => void): void {
  const render = (): void => {
    host.replaceChildren();
    const tabs = store.list();
    const active = store.active();
    if (tabs.length === 0) host.appendChild(buildHint());
    for (const t of tabs) host.appendChild(buildItem(t, active, store));
    host.appendChild(buildNewButton(onNew));
    host.dataset.empty = tabs.length === 0 ? "true" : "false";
  };
  store.subscribe(render);
  render();
}

function buildHint(): HTMLElement {
  const s = document.createElement("span");
  s.className = "tabs-hint";
  s.textContent = "no documents open — paste an address above";
  return s;
}

function buildNewButton(onNew: () => void): HTMLElement {
  const b = document.createElement("button");
  b.type = "button";
  b.className = "tab-new";
  b.textContent = "+";
  b.title = "new tab (Ctrl+T)";
  b.setAttribute("aria-label", "new tab");
  b.addEventListener("click", onNew);
  return b;
}

function buildItem(t: Tab, active: Tab | null, store: TabStore): HTMLElement {
  const item = document.createElement("button");
  item.type = "button";
  item.className = "tab";
  item.classList.add(`is-${t.status}`);
  if (active && t.id === active.id) item.classList.add("is-active");
  item.dataset.tabId = t.id;
  item.title = t.address ?? "empty tab";
  item.setAttribute("role", "tab");
  item.setAttribute("aria-selected", active && t.id === active.id ? "true" : "false");

  const label = document.createElement("span");
  label.className = "tab-label";
  label.textContent = t.shortLabel;
  item.appendChild(label);

  const close = document.createElement("span");
  close.className = "tab-close";
  close.textContent = "×";
  close.setAttribute("aria-label", "close tab");
  close.setAttribute("role", "button");
  close.addEventListener("click", (e) => {
    e.stopPropagation();
    store.close(t.id);
  });
  item.appendChild(close);

  item.addEventListener("click", () => store.activate(t.id));
  return item;
}
