//! CSV / tabular handler. Heuristic detection on UTF-8 content with
//! consistent comma-separated columns, then a minimal RFC 4180-ish
//! parse that respects double-quoted fields. Emits
//! [`Rendition::Tabular`] which UI shells render as a table.
//!
//! Conservative on purpose — random prose with one comma per line
//! shouldn't trip detection. We require at least 3 rows with at least
//! 2 consistent columns each.

use bytes::Bytes;

use crate::handler::{Confidence, ContentHandler, Hint, RenderContext, Rendition};
use crate::{Error, Result};

/// Recognises CSV / TSV — for now just CSV (commas).
#[derive(Debug, Default, Clone, Copy)]
pub struct CsvHandler;

const KIND: &str = "text/csv";
const BOM: &[u8] = &[0xEF, 0xBB, 0xBF];
const MIN_ROWS: usize = 3;
const MIN_COLUMNS: usize = 2;

fn strip_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(BOM).unwrap_or(bytes)
}

/// Split one CSV record at the top-level commas, respecting double
/// quotes. Doubled `""` inside a quoted field decodes to a single `"`.
fn split_record(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut in_quote = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, in_quote) {
            ('"', true) => {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    buf.push('"');
                } else {
                    in_quote = false;
                }
            }
            ('"', false) => in_quote = true,
            (',', false) => {
                out.push(std::mem::take(&mut buf));
            }
            (other, _) => buf.push(other),
        }
    }
    out.push(buf);
    out
}

/// Cheap structural sniff — multi-row, consistent-column shape.
fn looks_like_csv(text: &str) -> bool {
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| !l.is_empty())
        .take(10)
        .collect();
    if lines.len() < MIN_ROWS {
        return false;
    }
    let first_cols = split_record(lines[0]).len();
    if first_cols < MIN_COLUMNS {
        return false;
    }
    lines
        .iter()
        .all(|l| split_record(l).len() == first_cols)
}

impl ContentHandler for CsvHandler {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn can_handle(&self, head: &[u8], _hint: &Hint) -> Confidence {
        let head = strip_bom(head);
        if head.is_empty() || head.contains(&0u8) {
            return Confidence::None;
        }
        let Ok(text) = std::str::from_utf8(head) else {
            return Confidence::None;
        };
        if looks_like_csv(text) {
            // High beats TextHandler's Medium so CSV-shaped UTF-8 text
            // gets a structured render rather than plain prose.
            Confidence::High
        } else {
            Confidence::None
        }
    }

    fn render(&self, bytes: Bytes, _ctx: &RenderContext) -> Result<Rendition> {
        let stripped = strip_bom(&bytes);
        let text = std::str::from_utf8(stripped).map_err(|e| Error::Render {
            kind: KIND,
            reason: format!("invalid UTF-8: {e}"),
        })?;
        let mut lines = text.lines().filter(|l| !l.is_empty());
        let columns = lines.next().map(split_record).unwrap_or_default();
        let rows: Vec<Vec<String>> = lines.map(split_record).collect();
        Ok(Rendition::Tabular { columns, rows })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn confidence(text: &str) -> Confidence {
        CsvHandler.can_handle(text.as_bytes(), &Hint::default())
    }

    fn render(text: &str) -> Rendition {
        CsvHandler
            .render(
                Bytes::copy_from_slice(text.as_bytes()),
                &RenderContext::default(),
            )
            .expect("csv handler should not error on UTF-8")
    }

    #[test]
    fn claims_simple_csv() {
        let csv = "name,age,city\nalice,30,nyc\nbob,25,la\ncarol,40,sf\n";
        assert_eq!(confidence(csv), Confidence::High);
        match render(csv) {
            Rendition::Tabular { columns, rows } => {
                assert_eq!(columns, vec!["name", "age", "city"]);
                assert_eq!(rows.len(), 3);
                assert_eq!(rows[1], vec!["bob", "25", "la"]);
            }
            other => panic!("expected Tabular, got {other:?}"),
        }
    }

    #[test]
    fn handles_quoted_fields_with_commas() {
        let csv = "a,b,c\n\"x,y\",1,2\n\"z\",3,4\n\"q\",5,6\n";
        match render(csv) {
            Rendition::Tabular { rows, .. } => {
                assert_eq!(rows[0][0], "x,y");
                assert_eq!(rows[1][0], "z");
            }
            other => panic!("expected Tabular, got {other:?}"),
        }
    }

    #[test]
    fn handles_doubled_quotes() {
        let csv = "a,b\n\"she said \"\"hi\"\"\",1\n\"\"\",1\n\"x\",2\n";
        match render(csv) {
            Rendition::Tabular { rows, .. } => {
                assert_eq!(rows[0][0], "she said \"hi\"");
            }
            other => panic!("expected Tabular, got {other:?}"),
        }
    }

    #[test]
    fn rejects_single_row() {
        // No data rows under header — not enough to call CSV.
        assert_eq!(confidence("a,b,c\n"), Confidence::None);
    }

    #[test]
    fn rejects_inconsistent_columns() {
        // Looks like prose with commas, not a table.
        let prose = "Hello, world\nNice to see you, friend\nHow are things\n";
        assert_eq!(confidence(prose), Confidence::None);
    }

    #[test]
    fn rejects_single_column() {
        // No commas — not a table.
        let one_col = "alpha\nbeta\ngamma\ndelta\n";
        assert_eq!(confidence(one_col), Confidence::None);
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(confidence(""), Confidence::None);
    }

    #[test]
    fn rejects_binary() {
        assert_eq!(
            CsvHandler.can_handle(&[0u8, 0xFF, b'a', b','], &Hint::default()),
            Confidence::None,
        );
    }
}
