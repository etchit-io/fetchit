package io.etchit.fetchit

/**
 * Normalize a user-typed BIP39 recovery phrase before a restore attempt:
 * trim the ends, collapse every run of internal whitespace (stray double
 * spaces, tabs, or newlines pasted out of a note) down to a single space,
 * and lowercase. BIP39 words are lowercase ASCII, so this lets an otherwise
 * correct phrase match regardless of the keyboard's auto-capitalisation or
 * sloppy spacing.
 *
 * Pure and side-effect-free — no Android types — so it is unit-testable on
 * the JVM without a device (see `RecoveryPhraseTest`). It does no validation:
 * an actually-invalid phrase is rejected downstream by the FFI's BIP39 check.
 */
fun normalizeRecoveryPhrase(raw: String): String =
    raw.trim().replace(Regex("\\s+"), " ").lowercase()
