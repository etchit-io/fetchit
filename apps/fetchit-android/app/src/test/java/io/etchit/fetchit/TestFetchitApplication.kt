package io.etchit.fetchit

/**
 * Test Application for the Robolectric Activity tests. A real
 * [FetchitApplication] so the `fetchitApp()` casts in the UI hold, but
 * with the native-FFI bootstrap stubbed — there is no `.so` on the JVM.
 */
class TestFetchitApplication : FetchitApplication() {
    override fun bootstrapFfi() {
        // No native library off-device.
    }
}
