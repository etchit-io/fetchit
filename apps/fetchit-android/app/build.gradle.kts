import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Optional release-signing config. Populated from app/keystore.properties
// (gitignored). If the file is missing, release builds fall back to
// debug signing so contributors can still build without holding a
// release keystore. See RELEASING.md for the one-time setup.
val keystorePropsFile = file("keystore.properties")
val keystoreProps = Properties().apply {
    if (keystorePropsFile.exists()) {
        keystorePropsFile.inputStream().use { load(it) }
    }
}
val hasReleaseKeystore = keystoreProps.getProperty("storeFile") != null

android {
    namespace = "io.etchit.fetchit"
    compileSdk = 36

    // Pin matches the etchit-android NDK rev so prebuilt .so files
    // and the Rust toolchain stay aligned across the family.
    ndkVersion = "27.0.12077973"

    defaultConfig {
        applicationId = "io.etchit.fetchit"
        minSdk = 26
        targetSdk = 34
        versionCode = 7
        versionName = "0.2.5"

        ndk {
            // arm64 only — x86_64 is for emulators and bloats the APK
            // by ~half. If we ever need emulator support back, add
            // "x86_64" here and to scripts/build-jni-libs.sh.
            abiFilters += listOf("arm64-v8a")
        }
    }

    signingConfigs {
        if (hasReleaseKeystore) {
            create("release") {
                storeFile = file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".dev"
        }
        release {
            isMinifyEnabled = false
            signingConfig = if (hasReleaseKeystore) {
                signingConfigs.getByName("release")
            } else {
                // Debug-signed fallback: contributors without a release
                // keystore can still produce an installable APK.
                signingConfigs.getByName("debug")
            }
        }
    }

    buildFeatures {
        viewBinding = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }

    testOptions {
        // Pure-logic unit tests touch android.util.Log only for logging —
        // let the framework stubs return defaults instead of throwing, so
        // those files (e.g. EpubBook) are JVM-testable without a device.
        unitTests.isReturnDefaultValues = true
        // Robolectric Activity tests need the merged resources — themes,
        // drawables, layouts — on the unit-test classpath.
        unitTests.isIncludeAndroidResources = true
    }
}

dependencies {
    // uniffi-generated bindings call into JNA at runtime.
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    implementation("androidx.activity:activity-ktx:1.9.2")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.6")
    implementation("androidx.lifecycle:lifecycle-process:2.8.6")
    implementation("androidx.fragment:fragment-ktx:1.8.4")
    implementation("androidx.recyclerview:recyclerview:1.3.2")

    // Biometric — device re-auth (fingerprint / face / PIN / pattern / password)
    // gating the recovery-phrase reveal. Uses DEVICE_CREDENTIAL fallback so the
    // prompt works on devices without enrolled biometrics.
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.swiperefreshlayout:swiperefreshlayout:1.1.0")

    // Markwon — native markdown renderer for the text/markdown rendition.
    // Code-block syntax highlighting via the syntax-highlight plugin
    // requires Prism4j + an annotation-processor-generated grammar
    // locator; deferring that wiring to a follow-up since the basic
    // Markwon coverage already gives readable code blocks.
    implementation("io.noties.markwon:core:4.6.2")

    // Media3 — unified audio + video playback with built-in controls.
    // Replaces the older MediaPlayer / SurfaceView pair. PlayerView
    // ships play/pause, seek bar, time labels, ±15s skip out of the box.
    implementation("androidx.media3:media3-exoplayer:1.4.1")
    implementation("androidx.media3:media3-ui:1.4.1")
    implementation("androidx.media3:media3-datasource:1.4.1")

    // ZXing — QR-code encoder. Used for sharing autonomi:// addresses
    // as scannable images, since traditional messengers don't
    // linkify custom URL schemes.
    implementation("com.google.zxing:core:3.5.3")

    // ZXing Embedded — scanner Activity + ViewFinder. Fully self-
    // contained, no Google Play services dependency. Powers the
    // in-app "scan a QR" button so users can pull addresses off a
    // printed page or another phone's screen without leaving fetch>it.
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")

    // JVM unit tests — `./gradlew :app:testDebugUnitTest`, no device needed.
    // JUnit covers pure Kotlin; Robolectric runs tests that touch Android
    // framework classes (org.json, SharedPreferences, …) on the JVM.
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.14")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
    // Real org.json for plain-JVM tests: android.jar's stub throws "not
    // mocked", which silently nulled ChatController.decodePost under test.
    testImplementation("org.json:json:20240303")
}
