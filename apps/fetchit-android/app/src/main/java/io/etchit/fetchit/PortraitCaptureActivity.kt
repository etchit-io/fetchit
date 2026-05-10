package io.etchit.fetchit

import com.journeyapps.barcodescanner.CaptureActivity

/**
 * Forces the QR scanner into portrait orientation.
 *
 * `zxing-android-embedded`'s default [`CaptureActivity`] declares
 * `screenOrientation="sensorLandscape"` in its bundled manifest, which
 * beats any `setOrientationLocked(false)` we pass via [`ScanOptions`].
 * Empty subclass + a portrait `screenOrientation` declaration in our
 * own manifest is the standard escape hatch.
 *
 * Used implicitly by `MainActivity.onScanClicked` via
 * `ScanOptions.setCaptureActivity(PortraitCaptureActivity::class.java)`.
 */
class PortraitCaptureActivity : CaptureActivity()
