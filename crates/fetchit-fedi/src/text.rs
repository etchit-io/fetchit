//! Wire-HTML → plain-text reduction for feed rendering.
//!
//! Fediverse `Note.content` is HTML authored by a remote server. The v1
//! feed renders **text only** — reducing to plain text here means no
//! remote markup ever reaches a renderer, which kills the XSS surface
//! by construction rather than by sanitizer completeness. Block-level
//! closers become newlines so paragraphs survive the reduction.

/// Reduce a fediverse `Note.content` HTML fragment to display text.
///
/// - `<script>`/`<style>` elements are dropped WITH their contents.
/// - `<br>`, `</p>`, `</div>`, `</li>`, `</blockquote>` become newlines;
///   every other tag is stripped, keeping its text.
/// - The five XML entities plus decimal `&#NN;` references are decoded
///   (after tag stripping, so a decoded `<` can never form a tag).
/// - Runs of 3+ newlines collapse to a blank line; the result is trimmed.
#[must_use]
pub fn html_to_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut chars = html.char_indices().peekable();
    let bytes = html.as_bytes();
    while let Some((i, c)) = chars.next() {
        if c != '<' {
            out.push(c);
            continue;
        }
        // Find the tag end; an unterminated tag swallows the rest (it
        // could not have rendered anyway).
        let rest = &html[i + 1..];
        let Some(close_rel) = rest.find('>') else {
            break;
        };
        let tag_body = &rest[..close_rel];
        let tag_end = i + 1 + close_rel; // index of '>'
        let name: String = tag_body
            .trim_start_matches('/')
            .chars()
            .take_while(char::is_ascii_alphanumeric)
            .collect::<String>()
            .to_ascii_lowercase();
        let closing = tag_body.starts_with('/');
        match name.as_str() {
            "script" | "style" if !closing => {
                // Skip to the matching closer, dropping the contents.
                let closer = format!("</{name}");
                let after_tag = &html[tag_end + 1..];
                if let Some(rel) = after_tag.to_ascii_lowercase().find(&closer) {
                    let resume_from = tag_end + 1 + rel;
                    while let Some(&(j, _)) = chars.peek() {
                        if j > resume_from && bytes[j - 1] == b'>' {
                            break;
                        }
                        chars.next();
                    }
                } else {
                    break;
                }
            }
            "br" => out.push('\n'),
            "p" | "div" | "li" | "blockquote" if closing => out.push('\n'),
            _ => {}
        }
        // Consume up to and including '>' for non-script tags.
        while let Some(&(j, _)) = chars.peek() {
            if j > tag_end {
                break;
            }
            chars.next();
        }
    }
    let decoded = decode_entities(&out);
    collapse_newlines(&decoded).trim().to_owned()
}

fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let tail = &rest[amp..];
        let Some(semi) = tail[..tail.len().min(12)].find(';') else {
            out.push('&');
            rest = &rest[amp + 1..];
            continue;
        };
        let entity = &tail[1..semi];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" | "#39" => Some('\''),
            "nbsp" => Some(' '),
            _ => entity
                .strip_prefix('#')
                .and_then(|d| d.parse::<u32>().ok())
                .and_then(char::from_u32),
        };
        match decoded {
            Some(ch) => out.push(ch),
            None => out.push_str(&tail[..=semi]),
        }
        rest = &tail[semi + 1..];
    }
    out.push_str(rest);
    out
}

fn collapse_newlines(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut run = 0usize;
    for c in s.chars() {
        if c == '\n' {
            run += 1;
            if run <= 2 {
                out.push('\n');
            }
        } else {
            run = 0;
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn strips_tags_keeps_text_and_paragraph_breaks() {
        let html = "<p>hello <b>world</b></p><p>second <a href=\"https://x.example\">link</a></p>";
        assert_eq!(html_to_text(html), "hello world\nsecond link");
    }

    #[test]
    fn br_becomes_newline_and_runs_collapse() {
        assert_eq!(html_to_text("a<br><br><br><br>b"), "a\n\nb");
    }

    #[test]
    fn script_and_style_contents_are_dropped() {
        let html = "<p>safe</p><script>alert('x')</script><style>p{}</style><p>after</p>";
        let text = html_to_text(html);
        assert!(!text.contains("alert"), "got {text:?}");
        assert!(!text.contains("p{}"), "got {text:?}");
        assert!(
            text.contains("safe") && text.contains("after"),
            "got {text:?}"
        );
    }

    #[test]
    fn entities_decode_after_stripping_so_no_tag_can_form() {
        // &lt;script&gt; decodes to literal text, never markup — and since
        // the output is rendered as plain text, that is the whole story.
        let html = "&lt;script&gt;alert(1)&lt;/script&gt; &amp; more &#8212; dash";
        assert_eq!(
            html_to_text(html),
            "<script>alert(1)</script> & more \u{2014} dash"
        );
    }

    #[test]
    fn malformed_html_never_panics() {
        for bad in ["<", "a<b", "<p", "&", "&amp", "<script>never closed", "<>"] {
            let _ = html_to_text(bad);
        }
        assert_eq!(html_to_text("a<b"), "a");
    }

    #[test]
    fn mastodon_shaped_post_reads_naturally() {
        let html = "<p>Testing <span class=\"h-card\"><a href=\"https://m.example/@josh\" class=\"u-url mention\">@<span>josh</span></a></span> from fosstodon</p>";
        assert_eq!(html_to_text(html), "Testing @josh from fosstodon");
    }
}
