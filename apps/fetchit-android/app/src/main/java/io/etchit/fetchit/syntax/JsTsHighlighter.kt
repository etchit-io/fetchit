package io.etchit.fetchit.syntax

object JsTsHighlighter : SyntaxHighlighter {
    override val displayName = "JS / TS"

    private val keywords = setOf(
        "var", "let", "const", "function", "class", "extends", "new", "this", "super",
        "return", "yield", "async", "await",
        "if", "else", "for", "while", "do", "switch", "case", "default",
        "break", "continue", "try", "catch", "finally", "throw",
        "typeof", "instanceof", "in", "of",
        "import", "from", "export", "as",
        "interface", "type", "enum", "implements",
        "public", "private", "protected", "static", "readonly", "abstract",
        "namespace", "declare", "module",
    )
    // Common built-in globals + constructors — coloured as literals so the
    // typical browser/Node script gets visual punctuation around the
    // points where it touches the runtime.
    private val builtins = setOf(
        "document", "window", "globalThis", "self", "console", "navigator", "location",
        "history", "screen", "alert", "confirm", "prompt",
        "fetch", "Request", "Response", "Headers", "URL", "URLSearchParams",
        "setTimeout", "setInterval", "clearTimeout", "clearInterval",
        "requestAnimationFrame", "cancelAnimationFrame",
        "Math", "JSON", "Date", "Promise", "Symbol",
        "Array", "Object", "Number", "String", "Boolean", "BigInt",
        "Map", "Set", "WeakMap", "WeakSet",
        "Error", "TypeError", "RangeError", "SyntaxError", "ReferenceError",
        "RegExp", "Function", "Reflect", "Proxy",
        "Uint8Array", "Int8Array", "Uint16Array", "Int16Array",
        "Uint32Array", "Int32Array", "Float32Array", "Float64Array",
        "ArrayBuffer", "DataView",
    )
    private val keywordRe = Regex("\\b(${keywords.joinToString("|")})\\b")
    private val builtinRe = Regex("\\b(${builtins.joinToString("|")})\\b")
    private val literalRe = Regex("\\b(true|false|null|undefined|NaN|Infinity)\\b")
    private val commentLineRe = Regex("(?m)//.*$")
    private val commentBlockRe = Regex("(?s)/\\*.*?\\*/")
    private val stringRe = Regex(
        "\"(?:[^\"\\\\\\n]|\\\\.)*\"|'(?:[^'\\\\\\n]|\\\\.)*'|`(?:[^`\\\\]|\\\\.)*`",
    )
    private val numberRe = Regex("(?<![A-Za-z_])\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?")

    override fun tokenize(text: CharSequence): List<HighlightToken> {
        val s = text.toString()
        val out = mutableListOf<HighlightToken>()
        colorRule(out, s, numberRe, SyntaxColors.NUMBER)
        colorRule(out, s, builtinRe, SyntaxColors.LITERAL)
        colorRule(out, s, keywordRe, SyntaxColors.KEYWORD)
        colorRule(out, s, literalRe, SyntaxColors.LITERAL)
        colorRule(out, s, stringRe, SyntaxColors.STRING)
        colorRule(out, s, commentBlockRe, SyntaxColors.COMMENT)
        colorRule(out, s, commentLineRe, SyntaxColors.COMMENT)
        return out
    }
}
