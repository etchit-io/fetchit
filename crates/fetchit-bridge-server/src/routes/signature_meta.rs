//! Why an inbound delivery's HTTP Signature was rejected, in one log
//! line.
//!
//! A rejected federation delivery is close to undiagnosable from the
//! bare reason string: `signature invalid` collapses "the sender used a
//! wire format we reconstruct differently", "the sender signed a header
//! list we never rebuilt", "the signature belongs to a key we did not
//! verify against" and "an actual forgery" into one bucket. Remote
//! servers then retry the same rejected activity for days, so the cost
//! of guessing is measured in weeks.
//!
//! [`SignatureDiagnostics::collect`] reads ONLY the request's signature
//! metadata and re-derives what the verifier
//! (`inbox::verify_inbound_signature`) would have done, so a single
//! `warn!` explains a failure without a packet capture.
//!
//! # Privacy contract
//!
//! This module is append-only observability over IDENTIFIERS and
//! STRUCTURE. It must never surface:
//!
//! * the request body, or any field of the activity/object inside it,
//! * the signature payload, the `Digest`/`Content-Digest` VALUE, or any
//!   other header value that is not a fixed protocol token,
//! * message text of any kind.
//!
//! What it does surface: the `keyId` URL, the actor URL it is compared
//! against, header NAMES (never their values), the `algorithm` token,
//! the host candidates, and the request path. Adding a field that
//! carries a header VALUE breaks the contract — the presence map exists
//! precisely so values never have to be logged.
//!
//! # Not a gate
//!
//! Nothing here participates in the accept/reject decision. It runs
//! after the verifier has already returned `Err`, and its own parsing
//! is deliberately lenient: a diagnostic that fails to parse a
//! malformed header would blind us exactly when we most need to see.

use axum::http::HeaderMap;

/// Signature metadata for one rejected inbound delivery.
///
/// Every field is a `String` or a fixed token so the whole struct can
/// be splatted into a `tracing` event. Absent values are the empty
/// string rather than `Option`, so the rendered line always carries the
/// same field set and stays greppable.
pub(super) struct SignatureDiagnostics {
    /// Which wire format the verifier took: `rfc9421`, `cavage`, or
    /// `none` (no signature headers at all).
    pub(super) format: &'static str,
    /// RFC 9421 signature label — the `sig1` in `sig1=(...)`. Our
    /// verifier accepts `sig1` and nothing else, so a different label
    /// here is itself the answer. Empty on the cavage path.
    pub(super) label: String,
    /// `keyId` (cavage) / `keyid` (RFC 9421 signature params) — the key
    /// the SIGNER says it signed with. Empty when unparseable.
    pub(super) key_id: String,
    /// Does `key_id`'s owner (the `keyId` URL minus its `#fragment`)
    /// equal the activity's `actor`? `yes`, `no`, or `unknown` when
    /// there is no parseable `keyId`.
    ///
    /// The verifier derives its key from the ACTOR, not from `keyId`,
    /// so a `no` here means we verified against a key the signer never
    /// claimed to use.
    pub(super) key_id_owner_matches_actor: &'static str,
    /// The signer's declared `algorithm` (cavage) or `alg` (RFC 9421)
    /// token, verbatim. Empty when the signer omitted it.
    pub(super) algorithm: String,
    /// The signer's DECLARED covered-component list, space-separated
    /// and lowercased. Empty when the signer declared none.
    pub(super) signed_headers: String,
    /// Per-declared-component availability, as
    /// `name=present|absent|derived|unsupported` pairs.
    ///
    /// * `present` / `absent` — a real header, readable or not on this
    ///   request.
    /// * `derived` — reconstructed by the verifier rather than read
    ///   (`(request-target)`, RFC 9421 `@`-components).
    /// * `unsupported` — a cavage pseudo-header taken from the
    ///   signature parameters (`(created)`, `(expires)`); our verifier
    ///   looks these up as HTTP headers, never finds them, and fails.
    pub(super) signed_header_presence: String,
    /// The host candidates the verifier would try, in order, comma
    /// separated (public domain first, received `Host` second, deduped).
    pub(super) host_candidates: String,
    /// The path the verifier binds into `(request-target)` /
    /// `@target-uri`.
    pub(super) request_path: String,
}

impl SignatureDiagnostics {
    /// Re-derive the signature metadata for a delivery the verifier
    /// just rejected.
    ///
    /// `public_host` and `handle` must be the same values passed to the
    /// verifier, or the logged candidates/path will not describe the
    /// attempt that actually failed. `activity_actor` is the
    /// activity's `actor` field — the identity the verification key was
    /// fetched from.
    pub(super) fn collect(
        headers: &HeaderMap,
        handle: &str,
        public_host: &str,
        activity_actor: &str,
    ) -> Self {
        let request_path = format!("/actors/{handle}/inbox");
        let host_candidates = host_candidates(headers, public_host);

        // `Signature-Input` is the discriminator the verifier uses, so
        // the diagnostic must branch on exactly the same condition.
        let (format, label, key_id, algorithm, declared) =
            if let Some(sig_input) = header(headers, "signature-input") {
                let (label, components, params) = parse_signature_input(&sig_input);
                (
                    "rfc9421",
                    label,
                    param(&params, "keyid"),
                    param(&params, "alg"),
                    components,
                )
            } else if let Some(sig) = header(headers, "signature") {
                let params = parse_quoted_params(&sig);
                (
                    "cavage",
                    String::new(),
                    param(&params, "keyId"),
                    param(&params, "algorithm"),
                    param(&params, "headers")
                        .split_whitespace()
                        .map(str::to_lowercase)
                        .collect(),
                )
            } else {
                (
                    "none",
                    String::new(),
                    String::new(),
                    String::new(),
                    Vec::new(),
                )
            };

        Self {
            format,
            label,
            key_id_owner_matches_actor: owner_verdict(&key_id, activity_actor),
            key_id,
            algorithm,
            signed_header_presence: presence_map(headers, &declared),
            signed_headers: declared.join(" "),
            host_candidates,
            request_path,
        }
    }
}

/// The verifier's host-candidate list as a loggable string: public
/// domain first, the received `Host` second, collapsed when equal and
/// truncated to the public domain alone when no `Host` arrived.
fn host_candidates(headers: &HeaderMap, public_host: &str) -> String {
    match header(headers, "host") {
        Some(h) if h != public_host => format!("{public_host},{h}"),
        _ => public_host.to_owned(),
    }
}

/// `yes` / `no` / `unknown` for "is the `keyId` owned by the activity's
/// actor?".
///
/// Owner is the `keyId` URL with its `#fragment` stripped — the
/// `<actor>#main-key` convention every Mastodon-family server follows.
/// A `keyId` with no fragment (some Pleroma forks publish a standalone
/// key URL) simply compares as itself and reports `no`, which is the
/// honest answer: we cannot show it belongs to the actor.
fn owner_verdict(key_id: &str, activity_actor: &str) -> &'static str {
    if key_id.is_empty() {
        return "unknown";
    }
    let owner = key_id.split_once('#').map_or(key_id, |(base, _)| base);
    if owner == activity_actor {
        "yes"
    } else {
        "no"
    }
}

/// Render the declared component list as
/// `name=present|absent|derived|unsupported`, space separated.
fn presence_map(headers: &HeaderMap, declared: &[String]) -> String {
    declared
        .iter()
        .map(|name| format!("{name}={}", presence_of(headers, name)))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Classify one declared component. See
/// [`SignatureDiagnostics::signed_header_presence`] for what the tokens
/// mean.
fn presence_of(headers: &HeaderMap, name: &str) -> &'static str {
    // RFC 9421 derived components are reconstructed, never read.
    if name.starts_with('@') || name == "(request-target)" {
        return "derived";
    }
    // cavage pseudo-headers carried in the signature parameters. The
    // verifier resolves declared names through the HTTP header map, so
    // these can only ever come back missing.
    if name == "(created)" || name == "(expires)" {
        return "unsupported";
    }
    if header(headers, name).is_some() {
        "present"
    } else {
        "absent"
    }
}

/// Split an RFC 9421 `Signature-Input` value into its label, its
/// covered-component names (quotes stripped, lowercased) and its
/// trailing parameters.
///
/// Deliberately lenient: a value that does not match the shape yields
/// empty parts rather than an error, because the caller is already on
/// the failure path.
fn parse_signature_input(value: &str) -> (String, Vec<String>, Vec<(String, String)>) {
    let value = value.trim();
    let (label, rest) = match value.split_once('=') {
        Some((l, r)) => (l.trim().to_owned(), r),
        None => (String::new(), value),
    };
    let Some(open) = rest.find('(') else {
        return (label, Vec::new(), parse_quoted_params(rest));
    };
    let Some(close) = rest[open..].find(')').map(|i| open + i) else {
        return (label, Vec::new(), parse_quoted_params(rest));
    };
    let components = rest[open + 1..close]
        .split_whitespace()
        // A component may carry its own `;`-parameters
        // (`"@query-param";name="q"`); keep only the name so the
        // presence map stays a clean set of identifiers.
        .map(|c| {
            c.split(';')
                .next()
                .unwrap_or(c)
                .trim_matches('"')
                .to_lowercase()
        })
        .collect();
    (label, components, parse_quoted_params(&rest[close + 1..]))
}

/// Scan `key="value"` / `key=value` pairs out of a signature header,
/// splitting on `,` and `;` only OUTSIDE quotes so a base64 payload
/// containing separators cannot tear the list apart.
///
/// Never fails. Duplicate keys keep the first occurrence (see
/// [`param`]).
fn parse_quoted_params(value: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut in_quotes = false;
    let mut start = 0usize;
    let push = |chunk: &str, out: &mut Vec<(String, String)>| {
        let chunk = chunk.trim();
        if let Some((k, v)) = chunk.split_once('=') {
            let key = k.trim().to_owned();
            if !key.is_empty() {
                out.push((key, v.trim().trim_matches('"').to_owned()));
            }
        }
    };
    for (i, c) in value.char_indices() {
        if c == '"' {
            in_quotes = !in_quotes;
        } else if (c == ',' || c == ';') && !in_quotes {
            push(&value[start..i], &mut out);
            start = i + c.len_utf8();
        }
    }
    push(&value[start..], &mut out);
    out
}

/// First value for `key`, or the empty string. Case-sensitive: cavage
/// spells it `keyId`, RFC 9421 spells it `keyid`, and the caller asks
/// for the spelling its own wire format uses.
fn param(params: &[(String, String)], key: &str) -> String {
    params
        .iter()
        .find(|(k, _)| k == key)
        .map_or_else(String::new, |(_, v)| v.clone())
}

/// Read a header as a UTF-8 string.
///
/// Mirrors the verifier's own accessor (`inbox::header`) exactly,
/// including its treatment of a non-UTF-8 value as absent — the
/// presence map would lie if it reported `present` for a header the
/// verifier cannot read.
fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::http::{HeaderName, HeaderValue};

    const ACTOR: &str = "https://mastodon.example/users/alice";

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn cavage_headers(sig: &str) -> HeaderMap {
        headers(&[
            ("host", "bridge-origin.etchit.io"),
            ("date", "Mon, 03 Aug 2026 10:00:00 GMT"),
            ("digest", "SHA-256=Zm9v"),
            ("content-type", "application/activity+json"),
            ("signature", sig),
        ])
    }

    #[test]
    fn cavage_delivery_is_fully_described() {
        let sig = "keyId=\"https://mastodon.example/users/alice#main-key\",\
                   algorithm=\"rsa-sha256\",\
                   headers=\"(request-target) host date digest content-type\",\
                   signature=\"AAAA,BBBB==\"";
        let d = SignatureDiagnostics::collect(&cavage_headers(sig), "josh", "etchit.io", ACTOR);
        assert_eq!(d.format, "cavage");
        assert_eq!(d.key_id, "https://mastodon.example/users/alice#main-key");
        assert_eq!(d.key_id_owner_matches_actor, "yes");
        assert_eq!(d.algorithm, "rsa-sha256");
        assert_eq!(
            d.signed_headers,
            "(request-target) host date digest content-type"
        );
        assert_eq!(
            d.signed_header_presence,
            "(request-target)=derived host=present date=present digest=present \
             content-type=present"
        );
        assert_eq!(d.host_candidates, "etchit.io,bridge-origin.etchit.io");
        assert_eq!(d.request_path, "/actors/josh/inbox");
        assert!(d.label.is_empty(), "cavage carries no signature label");
    }

    #[test]
    fn declared_header_absent_from_request_is_named() {
        // The `signed header missing from request` class: the signer
        // covered a header the hop in front of us stripped.
        let sig = "keyId=\"k\",headers=\"(request-target) host date digest user-agent\",\
                   signature=\"AA\"";
        let d = SignatureDiagnostics::collect(&cavage_headers(sig), "josh", "etchit.io", ACTOR);
        assert!(
            d.signed_header_presence.contains("user-agent=absent"),
            "presence map must name the missing header: {}",
            d.signed_header_presence
        );
    }

    #[test]
    fn cavage_pseudo_headers_are_flagged_unsupported() {
        let sig = "keyId=\"k\",algorithm=\"hs2019\",\
                   headers=\"(request-target) (created) (expires) host date digest\",\
                   signature=\"AA\"";
        let d = SignatureDiagnostics::collect(&cavage_headers(sig), "josh", "etchit.io", ACTOR);
        assert_eq!(d.algorithm, "hs2019");
        assert!(d.signed_header_presence.contains("(created)=unsupported"));
        assert!(d.signed_header_presence.contains("(expires)=unsupported"));
    }

    #[test]
    fn rfc9421_delivery_reports_label_components_and_params() {
        let h = headers(&[
            ("host", "etchit.io"),
            ("date", "Mon, 03 Aug 2026 10:00:00 GMT"),
            ("content-digest", "sha-256=:Zm9v:"),
            (
                "signature-input",
                "sig1=(\"@method\" \"@target-uri\" \"content-digest\");\
                 created=1785000000;\
                 keyid=\"https://mastodon.example/users/alice#main-key\";\
                 alg=\"rsa-v1_5-sha256\"",
            ),
            ("signature", "sig1=:AAAA:"),
        ]);
        let d = SignatureDiagnostics::collect(&h, "josh", "etchit.io", ACTOR);
        assert_eq!(d.format, "rfc9421");
        assert_eq!(d.label, "sig1");
        assert_eq!(d.algorithm, "rsa-v1_5-sha256");
        assert_eq!(d.key_id, "https://mastodon.example/users/alice#main-key");
        assert_eq!(d.signed_headers, "@method @target-uri content-digest");
        assert_eq!(
            d.signed_header_presence,
            "@method=derived @target-uri=derived content-digest=present"
        );
        // Host header equals the public domain: one candidate only.
        assert_eq!(d.host_candidates, "etchit.io");
    }

    #[test]
    fn rfc9421_non_sig1_label_is_visible() {
        // Our verifier hard-requires `sig1=`; any other label is an
        // instant, silent rejection, so the label must be loggable.
        let h = headers(&[
            ("host", "etchit.io"),
            ("content-digest", "sha-256=:Zm9v:"),
            ("signature-input", "sig99=(\"@method\");keyid=\"k\""),
            ("signature", "sig99=:AAAA:"),
        ]);
        let d = SignatureDiagnostics::collect(&h, "josh", "etchit.io", ACTOR);
        assert_eq!(d.label, "sig99");
    }

    #[test]
    fn key_id_owned_by_someone_other_than_the_actor_is_flagged() {
        let sig = "keyId=\"https://relay.example/actor#main-key\",\
                   headers=\"(request-target) host date digest\",signature=\"AA\"";
        let d = SignatureDiagnostics::collect(&cavage_headers(sig), "josh", "etchit.io", ACTOR);
        assert_eq!(d.key_id_owner_matches_actor, "no");
        assert_eq!(d.key_id, "https://relay.example/actor#main-key");
    }

    #[test]
    fn unparseable_key_id_reports_unknown_owner() {
        let sig = "headers=\"(request-target) host date digest\",signature=\"AA\"";
        let d = SignatureDiagnostics::collect(&cavage_headers(sig), "josh", "etchit.io", ACTOR);
        assert_eq!(d.key_id_owner_matches_actor, "unknown");
        assert!(d.key_id.is_empty());
    }

    #[test]
    fn no_signature_headers_at_all_is_format_none() {
        let h = headers(&[("host", "etchit.io")]);
        let d = SignatureDiagnostics::collect(&h, "josh", "etchit.io", ACTOR);
        assert_eq!(d.format, "none");
        assert!(d.signed_headers.is_empty());
        assert!(d.signed_header_presence.is_empty());
    }

    #[test]
    fn missing_host_header_leaves_a_single_candidate() {
        let h = headers(&[("signature", "keyId=\"k\",headers=\"date\",signature=\"AA\"")]);
        let d = SignatureDiagnostics::collect(&h, "josh", "etchit.io", ACTOR);
        assert_eq!(d.host_candidates, "etchit.io");
        assert_eq!(d.signed_header_presence, "date=absent");
    }

    #[test]
    fn quote_aware_split_survives_separators_inside_the_payload() {
        // A base64 signature can contain `,` and `;` only if a peer
        // mangles it, but the parser must not lose `keyId` when it
        // does — the diagnostic is the last line of defence.
        let params = parse_quoted_params("keyId=\"a;b,c\",algorithm=\"rsa-sha256\"");
        assert_eq!(param(&params, "keyId"), "a;b,c");
        assert_eq!(param(&params, "algorithm"), "rsa-sha256");
    }

    #[test]
    fn header_name_case_is_normalised_in_the_declared_list() {
        // Signers are supposed to lowercase; some do not. The
        // presence map must still resolve them.
        let sig = "keyId=\"k\",headers=\"(request-target) Host Date Digest\",signature=\"AA\"";
        let d = SignatureDiagnostics::collect(&cavage_headers(sig), "josh", "etchit.io", ACTOR);
        assert_eq!(d.signed_headers, "(request-target) host date digest");
        assert_eq!(
            d.signed_header_presence,
            "(request-target)=derived host=present date=present digest=present"
        );
    }

    #[test]
    fn diagnostics_never_carry_a_header_value() {
        // Privacy contract, mechanically: no field may echo the digest
        // value, the signature payload, or the date value.
        let sig = "keyId=\"https://mastodon.example/users/alice#main-key\",\
                   algorithm=\"rsa-sha256\",\
                   headers=\"(request-target) host date digest content-type\",\
                   signature=\"c2VjcmV0LXNpZ25hdHVyZQ==\"";
        let d = SignatureDiagnostics::collect(&cavage_headers(sig), "josh", "etchit.io", ACTOR);
        let rendered = format!(
            "{} {} {} {} {} {} {} {}",
            d.format,
            d.label,
            d.key_id,
            d.algorithm,
            d.signed_headers,
            d.signed_header_presence,
            d.host_candidates,
            d.request_path
        );
        for leaked in [
            "c2VjcmV0LXNpZ25hdHVyZQ==",
            "SHA-256=Zm9v",
            "Mon, 03 Aug 2026 10:00:00 GMT",
        ] {
            assert!(
                !rendered.contains(leaked),
                "diagnostic leaked a header value: {leaked}"
            );
        }
    }
}
