package io.etchit.fetchit.syntax

/**
 * Map an explicit language tag (typically from `meta.lang` in an
 * etch/it envelope, or extracted via heuristic) to the matching
 * highlighter. Returns `null` for tags we don't have a tokenizer for —
 * caller should fall back to plain rendering.
 */
fun highlighterForLanguage(name: String?): SyntaxHighlighter? = when (name?.lowercase()) {
    null, "", "plain", "text" -> null
    "json", "jsonc" -> JsonHighlighter
    "bash", "sh", "shell", "zsh" -> BashHighlighter
    "python", "py" -> PythonHighlighter
    "javascript", "js", "jsx", "typescript", "ts", "tsx" -> JsTsHighlighter
    "kotlin", "kt", "kts" -> KotlinHighlighter
    "rust", "rs" -> RustHighlighter
    "go", "golang" -> GoHighlighter
    "html", "xml", "svg" -> HtmlHighlighter
    "css", "scss" -> CssHighlighter
    "yaml", "yml" -> YamlHighlighter
    "sql" -> SqlHighlighter
    else -> null
}

/**
 * Best-guess language from the buffer's content. Heuristic — first
 * non-blank line characteristics + a couple of whole-buffer shape
 * checks. Returns `null` when no pattern matches confidently — caller
 * falls back to plain rendering. Ported from etchit's `detectLanguage`.
 */
@Suppress("ReturnCount")
fun detectLanguageFromContent(text: CharSequence): SyntaxHighlighter? {
    val sample = text.toString().take(2000)
    if (sample.isBlank()) return null
    val firstLine = sample.lineSequence().firstOrNull { it.isNotBlank() }?.trim()
        ?: return null
    val lower = firstLine.lowercase()

    // Shebang
    if (firstLine.startsWith("#!")) return when {
        "python" in lower -> PythonHighlighter
        "node" in lower || "deno" in lower -> JsTsHighlighter
        else -> BashHighlighter
    }

    // HTML / XML
    if (lower.startsWith("<!doctype") || lower.startsWith("<html") ||
        lower.startsWith("<?xml")
    ) return HtmlHighlighter

    // JSON — whole-text shape
    val trimmed = text.toString().trim()
    if ((trimmed.startsWith("{") && trimmed.endsWith("}")) ||
        (trimmed.startsWith("[") && trimmed.endsWith("]"))
    ) {
        if (Regex("\"[\\w-]+\"\\s*:").containsMatchIn(trimmed.take(500))) return JsonHighlighter
    }

    // Python — def / class / import / from / decorator / dunder.
    if (Regex("^(def |class |import |from |if __name__|@\\w+)").containsMatchIn(firstLine))
        return PythonHighlighter

    // Kotlin (checked before JS/TS — `fun` / `val` / `var` are distinct).
    if (Regex("^(fun |val |var |package |object |class \\w+(\\s*:|\\s*\\())").containsMatchIn(firstLine))
        return KotlinHighlighter

    // JS / TS
    if (Regex("^(import|export|const|let|var|function|class|interface|type|async function|require\\()").containsMatchIn(firstLine))
        return JsTsHighlighter

    // Rust
    if (Regex("^(fn |use |mod |struct |enum |impl |pub |#!?\\[)").containsMatchIn(firstLine))
        return RustHighlighter

    // Go
    if (Regex("^(package |import |func )").containsMatchIn(firstLine))
        return GoHighlighter

    // SQL — case-insensitive on the leading verb.
    if (Regex("(?i)^(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|WITH|BEGIN)\\b").containsMatchIn(firstLine))
        return SqlHighlighter

    // CSS — rule blocks anywhere in the first 800 chars.
    if (Regex("(?m)^([.#]?[A-Za-z][\\w-]*|::?[\\w-]+|@\\w+)[\\w\\s.,#:>-]*\\{").containsMatchIn(sample.take(800)))
        return CssHighlighter

    // YAML — `key: value` shape on its own line.
    if (Regex("(?m)^[\\w-]+:\\s+\\S").containsMatchIn(sample.take(500)))
        return YamlHighlighter

    return null
}

/**
 * Choose a highlighter: explicit `lang` wins, otherwise content-based
 * detection, otherwise null. The single entry point wired into
 * [`io.etchit.fetchit.RenditionRenderer`].
 */
fun highlighterFor(language: String?, content: CharSequence): SyntaxHighlighter? =
    highlighterForLanguage(language) ?: detectLanguageFromContent(content)
