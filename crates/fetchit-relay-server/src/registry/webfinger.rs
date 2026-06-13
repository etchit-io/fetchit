//! Server-side WebFinger: parse `acct:<handle>@<domain>` and build the
//! JRD pointing at the canonical actor URL.

use crate::registry::ActorRecord;
use serde_json::{json, Value};

/// Parse a WebFinger `resource` of the form `acct:<handle>@<domain>`.
/// Returns `(handle, domain)`. Tolerates a leading `acct:` only.
///
/// # Errors
/// `Err(())` on any shape violation (maps to HTTP 400).
pub fn parse_acct_resource(resource: &str) -> Result<(String, String), ()> {
    let rest = resource.strip_prefix("acct:").ok_or(())?;
    let (handle, domain) = rest.split_once('@').ok_or(())?;
    if handle.is_empty() || domain.is_empty() || domain.contains('@') {
        return Err(());
    }
    Ok((handle.to_string(), domain.to_string()))
}

/// Build the JRD for a stored record.
#[must_use]
pub fn webfinger_jrd(record: &ActorRecord, domain: &str) -> Value {
    json!({
        "subject": format!("acct:{}@{}", record.handle, domain),
        "aliases": [record.actor_url],
        "links": [{
            "rel": "self",
            "type": "application/activity+json",
            "href": record.actor_url,
        }],
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::registry::tests_support::record_with;

    #[test]
    fn parses_well_formed_acct() {
        assert_eq!(
            parse_acct_resource("acct:josh@etchit.io").unwrap(),
            ("josh".to_string(), "etchit.io".to_string())
        );
    }

    #[test]
    fn rejects_missing_prefix_or_at() {
        for bad in [
            "josh@etchit.io",
            "acct:joshetchit.io",
            "acct:@etchit.io",
            "acct:josh@",
            "",
            "acct:a@b@c",
        ] {
            assert!(parse_acct_resource(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn jrd_self_link_points_at_actor_url() {
        let r = record_with("josh", "a".repeat(64), 5);
        let jrd = webfinger_jrd(&r, "etchit.io");
        assert_eq!(jrd["subject"], "acct:josh@etchit.io");
        assert_eq!(jrd["links"][0]["href"], "https://etchit.io/actors/josh");
        assert_eq!(jrd["links"][0]["type"], "application/activity+json");
    }
}
