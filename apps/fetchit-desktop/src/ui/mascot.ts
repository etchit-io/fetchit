// The fetcher mascot — an inline-SVG loading visual mounted by the
// controller while content loads. Driven by `download-progress`
// events through `applyProgress`; cleaned up by `dispose` when the
// renderer takes over.

import type { DownloadProgress } from "./downloadProgress";

/** Visible phase the mascot is currently rendering. */
export type MascotPhase = "idle-running" | "resolving" | "fetching" | "sprinting";

/** A live mascot instance — call [`applyProgress`](#applyProgress)
 *  on each `download-progress` event, and [`dispose`](#dispose) when
 *  the loading state ends. Disposing detaches the element and clears
 *  the blink / ear-flick timers. */
export interface MascotController {
  /** Detached DOM root — caller is responsible for attaching it
   *  somewhere visible (typically the tab content section). */
  readonly element: HTMLElement;
  /** Current phase, for tests and diagnostics. */
  readonly phase: MascotPhase;
  /** Update the mascot's visible state from a backend progress event. */
  applyProgress(p: DownloadProgress): void;
  /** Cancel idle-behavior timers and remove the element from the DOM. */
  dispose(): void;
}

// Registry so external callers — chiefly the download-progress
// listener — can find the live controller for a given tab without
// threading the reference through the controller layer.
const REGISTRY = new WeakMap<HTMLElement, MascotController>();

/** Find the live mascot mounted somewhere inside `container`, if
 *  any. Returns `undefined` once the mascot has been disposed. */
export function findMascotIn(container: HTMLElement): MascotController | undefined {
  const el = container.querySelector<HTMLElement>(".mascot");
  return el ? REGISTRY.get(el) : undefined;
}

/** Construct a fresh mascot. The element is *not* mounted — the
 *  caller decides where to attach it (typically as the only child of
 *  a freshly-emptied tab-content section). */
export function mountMascot(): MascotController {
  const root = document.createElement("div");
  root.className = "mascot mascot--idle-running";
  root.setAttribute("role", "status");
  root.setAttribute("aria-live", "polite");
  root.setAttribute("aria-label", "fetching");

  const stage = document.createElement("div");
  stage.className = "mascot-stage";
  root.appendChild(stage);

  // The SVG scene is a static literal — `DOMParser` parses it into
  // a real <svg> tree without ever evaluating script, so even though
  // the source is a string there is no XSS path.
  const svgDoc = new DOMParser().parseFromString(MASCOT_SCENE_SVG, "image/svg+xml");
  stage.appendChild(svgDoc.documentElement);

  const labelEl = document.createElement("p");
  labelEl.className = "mascot-label";
  labelEl.textContent = "fetching…";
  stage.appendChild(labelEl);

  const setLabel = (text: string): void => {
    labelEl.textContent = text;
  };

  // Rotate the goal-text phrases: add `.is-swapping` (fades to 0
  // via the CSS transition), replace `textContent` mid-fade, drop
  // the class so opacity returns to its state-driven value.
  const goalTextEl = stage.querySelector<SVGTextElement>(".mascot-goal-text");
  let goalIndex = Math.floor(Math.random() * MASCOT_TAGLINES.length);
  let goalRotateTimer = 0;
  if (goalTextEl) {
    goalTextEl.textContent = MASCOT_TAGLINES[goalIndex] ?? "";
  }
  const rotateGoalText = (): void => {
    if (disposed || !goalTextEl) return;
    goalTextEl.classList.add("is-swapping");
    window.setTimeout(() => {
      if (disposed) return;
      goalIndex = (goalIndex + 1) % MASCOT_TAGLINES.length;
      goalTextEl.textContent = MASCOT_TAGLINES[goalIndex] ?? "";
      goalTextEl.classList.remove("is-swapping");
    }, MASCOT_GOAL_SWAP_MS);
    goalRotateTimer = window.setTimeout(rotateGoalText, MASCOT_GOAL_ROTATE_MS);
  };
  goalRotateTimer = window.setTimeout(rotateGoalText, MASCOT_GOAL_ROTATE_MS);

  let phase: MascotPhase = "idle-running";
  let disposed = false;
  let blinkTimer = 0;
  let earTimer = 0;
  let tiltTimer = 0;

  const scheduleBlink = (): void => {
    if (disposed) return;
    blinkTimer = window.setTimeout(() => {
      root.classList.add("is-blinking");
      window.setTimeout(() => root.classList.remove("is-blinking"), 160);
      scheduleBlink();
    }, 3500 + Math.random() * 4500);
  };
  const scheduleEarFlick = (): void => {
    if (disposed) return;
    earTimer = window.setTimeout(() => {
      root.classList.add("is-ear-flicking");
      window.setTimeout(() => root.classList.remove("is-ear-flicking"), 600);
      scheduleEarFlick();
    }, 8000 + Math.random() * 9000);
  };
  const scheduleHeadTilt = (): void => {
    if (disposed) return;
    tiltTimer = window.setTimeout(() => {
      if (phase === "resolving") {
        root.classList.add("is-head-tilting");
        window.setTimeout(() => root.classList.remove("is-head-tilting"), 900);
      }
      scheduleHeadTilt();
    }, 5500 + Math.random() * 6500);
  };

  scheduleBlink();
  scheduleEarFlick();
  scheduleHeadTilt();

  const setPhase = (next: MascotPhase): void => {
    if (phase === next) return;
    root.classList.remove(`mascot--${phase}`);
    root.classList.add(`mascot--${next}`);
    phase = next;
  };

  const controller: MascotController = {
    element: root,
    get phase() {
      return phase;
    },
    applyProgress(p: DownloadProgress) {
      if (p.phase === "resolving") {
        setPhase("resolving");
        setLabel("sniffing the trail…");
        return;
      }
      const pct = p.total > 0
        ? Math.min(100, Math.round((p.done / p.total) * 100))
        : 0;
      setPhase(pct >= 90 ? "sprinting" : "fetching");
      setLabel(`fetching ${pct}%`);
    },
    dispose() {
      if (disposed) return;
      disposed = true;
      window.clearTimeout(blinkTimer);
      window.clearTimeout(earTimer);
      window.clearTimeout(tiltTimer);
      window.clearTimeout(goalRotateTimer);
      REGISTRY.delete(root);
      root.remove();
    },
  };
  REGISTRY.set(root, controller);
  return controller;
}

// Phrases the goal-text cycles through.
const MASCOT_TAGLINES: readonly string[] = [
  "browse spyware free",
  "browse without tracking",
];
/** Time the rotation waits before swapping to the next phrase. */
const MASCOT_GOAL_ROTATE_MS = 4200;
/** Fade-out window inside which the text content is swapped. Must
 *  match the CSS transition duration on `.mascot-goal-text`. */
const MASCOT_GOAL_SWAP_MS = 320;

// Ground tick marks — short strokes spaced every 30 units across a
// 720-wide scene. Drawn once; the parent group animates translateX
// by exactly the spacing, so the loop is seamless.
function groundTickMarkup(): string {
  const ticks: string[] = [];
  for (let x = -30; x <= 750; x += 30) {
    ticks.push(
      `<line class="mascot-ground-tick" x1="${x}" y1="218" x2="${x + 5}" y2="223" />`,
    );
  }
  return ticks.join("");
}

// One articulated leg: upper segment around the shoulder/hip pivot,
// lower segment nested in its own group around the knee/elbow so
// CSS rotations compose (upper sweep × lower bend). `kind` /
// `side` pick the matching CSS animation + depth shading.
function legMarkup(kind: "front" | "back", side: "near" | "far", x: number, y: number): string {
  const upperLen = 11;
  const lowerLen = 12;
  const kneeX = x;
  const kneeY = y + upperLen;
  const pawX = x;
  const pawY = kneeY + lowerLen;
  return `
    <g class="puppy-leg puppy-leg--${kind} puppy-leg--${kind}-${side}" style="transform-origin: ${x}px ${y}px;">
      <line class="puppy-leg-upper" x1="${x}" y1="${y}" x2="${kneeX}" y2="${kneeY}" />
      <g class="puppy-leg-knee" style="transform-origin: ${kneeX}px ${kneeY}px;">
        <line class="puppy-leg-lower" x1="${kneeX}" y1="${kneeY}" x2="${pawX}" y2="${pawY}" />
        <ellipse class="puppy-leg-paw" cx="${pawX}" cy="${pawY + 1}" rx="5.5" ry="2.8" />
      </g>
    </g>
  `;
}

// ViewBox: 720x280, ground at y=215. The landscape groups use the
// `mascotWobbleSoft` filter (feTurbulence + feDisplacementMap); the
// `.puppy` group does not — color-zone fills smear under the filter.
const MASCOT_SCENE_SVG = `<svg class="mascot-svg" viewBox="0 0 720 280" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <defs>
    <filter id="mascotWobbleSoft" x="-2%" y="-2%" width="104%" height="104%">
      <feTurbulence type="fractalNoise" baseFrequency="0.04" numOctaves="2" seed="3" />
      <feDisplacementMap in="SourceGraphic" scale="0.9" />
    </filter>
    <linearGradient id="mascotSky" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" class="mascot-sky-top" />
      <stop offset="100%" class="mascot-sky-bottom" />
    </linearGradient>
  </defs>

  <rect class="mascot-paper" x="0" y="0" width="720" height="215" fill="url(#mascotSky)" />

  <g class="mascot-hills" filter="url(#mascotWobbleSoft)">
    <path class="mascot-hill" d="M -60 195 C 30 175, 120 188, 200 178 C 260 170, 320 192, 400 182 C 470 173, 540 192, 620 180 C 680 172, 740 188, 800 184 L 800 215 L -60 215 Z" />
  </g>

  <g class="mascot-clouds" filter="url(#mascotWobbleSoft)">
    <g class="mascot-cloud mascot-cloud--a">
      <circle cx="120" cy="60" r="12" />
      <circle cx="138" cy="57" r="15" />
      <circle cx="155" cy="60" r="11" />
      <circle cx="142" cy="47" r="10" />
    </g>
    <g class="mascot-cloud mascot-cloud--b">
      <circle cx="420" cy="40" r="9" />
      <circle cx="434" cy="38" r="11" />
      <circle cx="446" cy="42" r="8" />
    </g>
    <g class="mascot-cloud mascot-cloud--c">
      <circle cx="600" cy="85" r="10" />
      <circle cx="615" cy="81" r="13" />
      <circle cx="630" cy="84" r="9" />
      <circle cx="620" cy="71" r="7" />
    </g>
  </g>

  <g class="mascot-ground" filter="url(#mascotWobbleSoft)">
    <path class="mascot-ground-line" d="M -10 215 L 730 215" />
    <g class="mascot-ground-ticks">${groundTickMarkup()}</g>
  </g>

  <g class="mascot-dust">
    <circle class="mascot-dust-puff mascot-dust-puff--1" r="7" cx="245" cy="210" />
    <circle class="mascot-dust-puff mascot-dust-puff--2" r="10" cx="220" cy="212" />
    <circle class="mascot-dust-puff mascot-dust-puff--3" r="12" cx="195" cy="213" />
  </g>

  <!-- Element order is paint order: back-side elements before
       front-side, underlayers before overlays. -->
  <g class="puppy">

    <g class="puppy-tail-wrap" style="transform-origin: 252px 166px;">
      <path class="puppy-tail-fill" d="M 252 166 Q 240 145, 250 130 Q 258 135, 258 158 Z" />
      <path class="puppy-tail-tip" d="M 250 130 Q 256 132, 258 142 L 254 142 Q 254 134, 250 130 Z" />
    </g>

    ${legMarkup("back", "far", 268, 178)}
    ${legMarkup("back", "near", 280, 178)}

    <ellipse class="puppy-body" cx="320" cy="178" rx="62" ry="26" />
    <ellipse class="puppy-belly" cx="320" cy="190" rx="55" ry="14" />
    <path class="puppy-saddle" d="M 268 158 Q 320 145, 372 158 L 368 178 Q 320 185, 272 178 Z" />

    <ellipse class="puppy-collar" cx="378" cy="170" rx="10" ry="3.5" />
    <g class="puppy-collar-tag-wrap" style="transform-origin: 380px 172px;">
      <circle class="puppy-collar-tag" cx="380" cy="176" r="3.2" />
    </g>

    ${legMarkup("front", "far", 360, 178)}
    ${legMarkup("front", "near", 372, 178)}

    <g class="puppy-head-wrap" style="transform-origin: 388px 134px;">

      <g class="puppy-ear puppy-ear--back" style="transform-origin: 372px 115px;">
        <path class="puppy-ear-back-fill" d="M 372 115 Q 358 122, 354 145 Q 354 162, 364 168 Q 376 165, 380 145 Q 384 125, 380 115 Z" />
        <path class="puppy-ear-back-shadow" d="M 372 115 Q 358 122, 354 145 Q 354 162, 364 168 L 360 158 Q 360 130, 376 117 Z" />
      </g>

      <circle class="puppy-head" cx="388" cy="130" r="32" />
      <path class="puppy-skullcap" d="M 358 124 Q 388 100, 418 122 Q 416 130, 388 132 Q 360 130, 358 124 Z" />

      <ellipse class="puppy-snout" cx="420" cy="142" rx="16" ry="11" />
      <ellipse class="puppy-snout-light" cx="420" cy="148" rx="14" ry="6" />

      <path class="puppy-mouth" d="M 412 150 Q 422 156 432 148" />

      <g class="puppy-tongue-wrap" style="transform-origin: 425px 152px;">
        <path class="puppy-tongue" d="M 423 152 Q 432 162, 428 174 Q 421 168, 419 154 Z" />
      </g>

      <ellipse class="puppy-nose" cx="434" cy="138" rx="5" ry="4" />
      <ellipse class="puppy-nose-highlight" cx="432" cy="136" rx="1.6" ry="1.2" />

      <g class="puppy-eye-wrap">
        <circle class="puppy-eye-white" cx="384" cy="124" r="8" />
        <circle class="puppy-pupil" cx="386" cy="125" r="5.2" />
        <circle class="puppy-eye-highlight" cx="388" cy="122" r="2" />
        <ellipse class="puppy-eyelid" cx="384" cy="124" rx="8" ry="8.5" />
      </g>

      <g class="puppy-brow-wrap">
        <path class="puppy-brow" d="M 376 112 Q 384 109 392 113" />
      </g>

      <g class="puppy-ear puppy-ear--front" style="transform-origin: 372px 118px;">
        <path class="puppy-ear-front-fill" d="M 372 118 Q 358 132, 356 158 Q 358 176, 372 178 Q 384 175, 386 152 Q 388 130, 380 118 Z" />
        <path class="puppy-ear-front-shadow" d="M 372 118 Q 358 132, 356 158 Q 358 176, 372 178 L 368 168 Q 366 138, 380 122 Z" />
      </g>
    </g>
  </g>

  <text class="mascot-goal-text" x="640" y="200" text-anchor="middle">browse spyware free</text>
</svg>`;
