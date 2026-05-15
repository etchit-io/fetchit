package io.etchit.fetchit

import androidx.annotation.StyleRes

/**
 * The three brand-aligned theme palettes. Token values live in
 * `res/values/themes.xml`; see docs/BRAND.md for the canonical
 * role / value mapping shared with the desktop app.
 *
 * Switching theme requires an [android.app.Activity.recreate] after
 * persisting the new choice — Android resolves theme attributes at
 * Activity inflation time, not on a [`Resources.Theme`] mutate.
 */
enum class Theme(val id: String, @StyleRes val styleRes: Int) {
    Dark("dark", R.style.Theme_Fetchit_Dark),
    Dim("dim", R.style.Theme_Fetchit_Dim),
    Light("light", R.style.Theme_Fetchit_Light);

    companion object {
        fun fromId(id: String): Theme? = entries.firstOrNull { it.id == id }
    }
}
