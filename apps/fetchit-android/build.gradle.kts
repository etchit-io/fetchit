// Toolchain mirrors etchit-android: AGP 8.9.1 + Kotlin 2.2.10. Bumping
// either is a deliberate decision — keeps the family on the same
// build path for parity with `etchit/build.gradle.kts`.
plugins {
    id("com.android.application") version "8.9.1" apply false
    id("org.jetbrains.kotlin.android") version "2.2.10" apply false
}
