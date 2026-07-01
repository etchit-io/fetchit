// WebdriverIO config — fetch>it desktop E2E. Drives the built Tauri app
// via `tauri-driver`, which proxies to the platform webview driver
// (`WebKitWebDriver` on Linux). Run from apps/fetchit-desktop with
// `npm run e2e`; needs `tauri-driver`, `WebKitWebDriver` (apt
// `webkit2gtk-driver`) and an X server (`xvfb-run` when headless).
// Linux/Windows only — `tauri-driver` has no macOS support.

import { spawn, spawnSync } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";

/** tauri-driver child process; spawned per session, killed after. */
let tauriDriver;

export const config = {
  hostname: "127.0.0.1",
  port: 4444,
  specs: ["./e2e/**/*.spec.mjs"],
  maxInstances: 1,
  capabilities: [
    {
      maxInstances: 1,
      // The cargo debug binary onPrepare builds — named for the
      // src-tauri crate (fetchit-desktop), not tauri.conf's productName.
      "tauri:options": {
        application: new URL(
          "./src-tauri/target/debug/fetchit-desktop",
          import.meta.url,
        ).pathname,
      },
    },
  ],
  reporters: ["spec"],
  framework: "mocha",
  mochaOpts: { ui: "bdd", timeout: 60_000 },
  logLevel: "warn",

  // Build the debug binary up front — the `e2e` feature has the backend
  // serve fixtures instead of fetching; executable only, no bundle.
  onPrepare: () => {
    const build = spawnSync(
      "npm",
      ["run", "tauri", "build", "--", "--debug", "--no-bundle", "--features", "e2e"],
      { stdio: "inherit" },
    );
    if (build.status !== 0) {
      throw new Error(`tauri debug build failed (exit ${build.status})`);
    }
  },

  // tauri-driver must be up before each WebDriver session.
  beforeSession: () => {
    tauriDriver = spawn(join(homedir(), ".cargo", "bin", "tauri-driver"), [], {
      stdio: [null, process.stdout, process.stderr],
    });
  },

  afterSession: () => {
    tauriDriver?.kill();
  },
};
