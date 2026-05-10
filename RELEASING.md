# Releasing fetch/it

Release process for the Android APK. Other artifacts (CLI binaries,
WASM viewer, Tauri desktop) get their own pipelines later.

## TL;DR

```
# bump version
$EDITOR apps/fetchit-android/app/build.gradle.kts   # versionCode + versionName
git commit -am "release: v0.1.0"
git tag v0.1.0
git push origin main --tags
```

The `release.yml` workflow picks up the tag, builds a signed APK, and
publishes it to GitHub Releases as `fetchit-0.1.0.apk` plus a
`.sha256` checksum.

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

## Per-release process

1. **Bump the version** in `apps/fetchit-android/app/build.gradle.kts`:

   ```kotlin
   versionCode = 2          // monotonic — Android refuses downgrades
   versionName = "0.1.0"    // semantic version (no `v` prefix)
   ```

2. **Smoke-test the build locally** (catches signing-config issues
   before CI):

   ```
   ./scripts/build-jni-libs.sh
   cd apps/fetchit-android
   ./gradlew :app:assembleRelease
   adb install -r app/build/outputs/apk/release/app-release.apk
   ```

3. **Commit, tag, push**:

   ```
   git commit -am "release: v0.1.0"
   git tag v0.1.0
   git push origin main --tags
   ```

4. **Watch the workflow**: GitHub Actions → `release` → look for the
   tag. Takes ~5–10 minutes. Output is a Release on the repo's
   Releases page with the APK + sha256 attached.

5. **Verify the download**: pull the published APK, compare its
   sha256 against the `.sha256` file, install it on a clean device.

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
  release with a higher `versionCode` upgrades them.

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
- **Reproducible builds** — gradle's `assembleRelease` is mostly but
  not perfectly deterministic. Independent verification of a published
  APK requires the same NDK / JDK / Rust toolchain versions plus the
  keystore.
