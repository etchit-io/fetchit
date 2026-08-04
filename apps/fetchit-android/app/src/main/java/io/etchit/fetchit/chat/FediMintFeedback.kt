package io.etchit.fetchit.chat

import uniffi.fetchit_ffi.MintRegistrationFfi
import uniffi.fetchit_ffi.MintStateFfi

/**
 * The @name the directory refused as someone else's, or `null` when the
 * outcome was anything else.
 *
 * The engine has already made the call — the bridge answers 409 only when a
 * DIFFERENT identity holds the handle — so the screen never has to guess
 * which failures are worth retrying: this one is not.
 */
fun takenHandle(registration: MintRegistrationFfi): String? =
    (registration as? MintRegistrationFfi.NameTaken)?.handle

/**
 * The @name refused in the last recorded mint attempt, from the state the
 * engine persisted. Survives a restart, so the mint screen can reopen on the
 * failing name instead of forgetting the conflict ever happened.
 */
fun takenHandle(state: MintStateFfi?): String? =
    state?.let { takenHandle(it.registration) }
