# Releasing fetch>it

A single `v*` tag releases every platform in one pass:

| Platform | Artifact(s) attached to the Release |
|----------|--------------------------------------|
| Android  | `fetchit-<ver>.apk` + `.sha256`, plus stable-named `app-release.apk` |
| macOS    | Universal `.dmg` + `.app.tar.gz` (Apple Silicon + Intel in one bundle) |
| Linux    | `.deb` (x86_64) |
| Windows  | `.msi` + NSIS `.exe` (x86_64) |

All five artifacts land on the same GitHub Release because both jobs
in `.github/workflows/release.yml` upsert against the same tag.

## TL;DR

```
# 1. Keep versions in sync across the three projects:
$EDITOR apps/fetchit-android/app/build.gradle.kts   # versionCode + versionName
$EDITOR apps/fetchit-desktop/src-tauri/tauri.conf.json   # "version"
$EDITOR apps/fetchit-desktop/package.json           # "version"

# 2. Tag + push:
git commit -am "release: v0.1.0"
git tag v0.1.0
git push --follow-tags origin main
```

The Android job (`release-apk`) finishes in ~5–10 min; the desktop
matrix (`release-desktop`, 3 runners in parallel) takes ~15–25 min
because Tauri compiles the Rust backend from scratch on each OS.

## One-time setup

### 1. Generate a release keystore

The keystore signs every release APK. **Lose it and you can never
update the app** — Android refuses installs of an APK signed with a
different key than the one already installed. Back it up somewhere
safe (encrypted volume, password manager attachment, etc.).

```
cd apps/fetchit-android/app
keytool -genkeypair -v \
  -keystore fetchit-release.keystore \
  -alias fetchit \
  -keyalg RSA -keysize 2048 -validity 10000
```

`keytool` will prompt for a keystore password, key password, and your
identity (org name, country, etc.). Use a long randomly-generated
password — store it in a password manager. The keystore itself is
gitignored.

### 2. Configure local builds

```
cp apps/fetchit-android/app/keystore.properties.template \
   apps/fetchit-android/app/keystore.properties
$EDITOR apps/fetchit-android/app/keystore.properties
```

Fill in the passwords you used in step 1. With this in place,
`./gradlew :app:assembleRelease` produces a properly-signed APK.
Without it, release builds fall back to debug signing (fine for
testing, not OK for distribution).

### 3. Configure GitHub Actions

The release workflow needs the keystore + passwords as repo secrets.

```
# encode the keystore as base64
base64 -w0 apps/fetchit-android/app/fetchit-release.keystore > /tmp/fetchit-keystore.b64
```

In your GitHub repo, **Settings → Secrets and variables → Actions →
New repository secret**, add four secrets:

| Secret              | Value                                                    |
|---------------------|----------------------------------------------------------|
| `KEYSTORE_BASE64`   | contents of `/tmp/fetchit-keystore.b64`                  |
| `KEYSTORE_PASSWORD` | the keystore password from step 1                        |
| `KEY_ALIAS`         | `fetchit` (or whatever alias you used)                   |
| `KEY_PASSWORD`      | the key password from step 1 (often same as keystore PW) |

Then `rm /tmp/fetchit-keystore.b64`.

### 4. Desktop code-signing (OPTIONAL — unsigned bundles still publish)

The desktop matrix runs without any of these secrets. Bundles publish
unsigned and users see a one-time warning the first time they open
the app:

- **macOS unsigned**: Gatekeeper blocks; user clicks System Settings →
  Privacy & Security → "Open Anyway" once. Notarised builds skip this.
- **Windows unsigned**: SmartScreen flags as unknown; user clicks
  "More info" → "Run anyway". Authenticode-signed builds skip this.
- **Linux**: no equivalent gating; `.deb` runs as-is.

When (if) you want to remove those warnings, set up the certs and
upload them as repo secrets.

**Apple Developer ID** ($99/yr, [developer.apple.com](https://developer.apple.com)):

| Secret                       | What                                                   |
|------------------------------|--------------------------------------------------------|
| `APPLE_CERTIFICATE`          | base64 of the .p12 export of the Developer ID cert     |
| `APPLE_CERTIFICATE_PASSWORD` | the .p12 export password                               |
| `APPLE_SIGNING_IDENTITY`     | `Developer ID Application: <Your Name> (<TEAM_ID>)`    |
| `APPLE_ID`                   | the Apple ID email used to enroll                      |
| `APPLE_PASSWORD`             | an app-specific password from appleid.apple.com        |
| `APPLE_TEAM_ID`              | 10-char team identifier from the Developer portal      |

**Windows Authenticode** (DigiCert, Sectigo, etc. — ~$200–500/yr):

| Secret                          | What                                          |
|---------------------------------|-----------------------------------------------|
| `WINDOWS_CERTIFICATE`           | base64 of the .pfx file                       |
| `WINDOWS_CERTIFICATE_PASSWORD`  | .pfx export password                          |

The workflow's "Stage Windows signing certificate" step decodes the
PFX into `$RUNNER_TEMP` and exports its path so `tauri-action`'s
bundler picks it up automatically. Missing secret → step logs "not
configured" and the bundle ships unsigned.

## Per-release process

1. **Bump the version in all three files** (they must agree):

   ```kotlin
   // apps/fetchit-android/app/build.gradle.kts
   versionCode = 2          // monotonic — Android refuses downgrades
   versionName = "0.1.0"    // semantic version (no `v` prefix)
   ```

   ```json
   // apps/fetchit-desktop/src-tauri/tauri.conf.json
   "version": "0.1.0"
   ```

   ```json
   // apps/fetchit-desktop/package.json
   "version": "0.1.0"
   ```

   **If you also publish the Rust crates** (not part of this pipeline
   today, but for completeness): bump `version` in **both**
   `Cargo.toml` (the `[workspace.package]` block) **and**
   `crates/fetchit-ffi/Cargo.toml` (the `[package]` block). The FFI
   crate sits outside the main workspace by design and can't inherit
   `version.workspace = true`, so the value lives in two places that
   must stay in sync.

2. **Smoke-test both builds locally** (catches config drift before CI):

   ```
   # Android signed APK
   ./scripts/build-jni-libs.sh
   cd apps/fetchit-android && ./gradlew :app:assembleRelease && cd -
   adb install -r apps/fetchit-android/app/build/outputs/apk/release/app-release.apk

   # Desktop bundle for the host OS
   cd apps/fetchit-desktop
   npm ci
   npm run tauri build
   ```

   Local `tauri build` only produces a bundle for the host OS — the
   cross-platform fan-out is the matrix's job.

3. **Commit, tag, push**:

   ```
   git commit -am "release: v0.1.0"
   git tag v0.1.0
   git push --follow-tags origin main
   ```

4. **Watch the workflow**: GitHub Actions → `release` → look for the
   tag. APK job ~5–10 min; desktop matrix ~15–25 min for all three
   runners. Output is one Release on the repo's Releases page with
   APK + macOS .dmg + Linux .deb + Windows .msi/.exe.

5. **Verify the downloads**: pull each artifact, compare APK sha256
   against the `.sha256` file, install on a clean device / VM /
   machine of each kind.

## Tag conventions

| Tag pattern   | Behaviour                                                |
|---------------|----------------------------------------------------------|
| `v0.1.0`      | Stable release (auto-published)                          |
| `v0.1.0-rc1`  | Pre-release (workflow flags `prerelease: true`)          |
| `v0.1.0-dev`  | Pre-release (same — anything with `-` in version)        |

Workflow uses `contains(version, '-')` to flag pre-releases on the
GitHub Releases page.

## Rolling back

GitHub Releases is the source of truth. To unrelease:

- **Soft delete**: Releases → … → "delete release". Tag stays in git.
- **Hard delete**: also delete the tag (`git push --delete origin v0.1.0`).
  Local users with the bad APK installed are stuck on it; the next
  release with a higher `versionCode` upgrades them. Desktop users
  who already downloaded a bad bundle keep it until they redownload —
  unlike Android there's no upgrade-refuses-downgrade enforcement, so
  bumping the version and re-releasing is the cleanest fix.

Never reuse a `versionCode`. Even after deleting a release, the next
release must have a strictly higher `versionCode` than any APK that
was ever published, because clients in the wild may have it installed
already.

## What this pipeline does NOT do (yet)

- **x86_64 / emulator support** — disabled to keep the APK small.
  Real phones are arm64 (99%+); x86_64 is only useful in emulators.
  If we need emulator builds, add `x86_64` back to `abiFilters` in
  `app/build.gradle.kts` and to `scripts/build-jni-libs.sh`.
- **Play Store upload** — manual for now. The signing key is
  upload-key compatible if/when we go through Play App Signing.
- **ARM Linux / ARM Windows desktop bundles** — only x86_64 today.
  macOS is universal so Apple Silicon is covered. Add `linux/arm64`
  or `windows-11-arm` matrix legs when there's user demand.
- **Auto-update for desktop** — bundles are install-once. Wire
  `tauri-plugin-updater` + signed update manifests when we want
  background updates.
- **Reproducible builds** — gradle's `assembleRelease` is mostly but
  not perfectly deterministic. Independent verification of a published
  APK requires the same NDK / JDK / Rust toolchain versions plus the
  keystore.
