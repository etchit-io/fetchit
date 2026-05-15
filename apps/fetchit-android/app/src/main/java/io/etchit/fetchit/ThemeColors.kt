package io.etchit.fetchit

import android.content.Context
import android.util.TypedValue
import androidx.annotation.AttrRes

/**
 * Resolve a theme attribute (e.g. [R.attr.fetchitInk]) to its current
 * per-theme color int.
 *
 * Recomputed at call-time so a recreate()-driven theme switch reflects
 * immediately. Use this anywhere a color needs to be set programmatically
 * — view layouts can reference `?attr/fetchitInk` directly.
 */
fun Context.themeColor(@AttrRes id: Int): Int {
    val tv = TypedValue()
    theme.resolveAttribute(id, tv, true)
    return tv.data
}
