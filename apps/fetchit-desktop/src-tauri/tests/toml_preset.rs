//! Verifies the bundled x0xd TOML template is syntactically valid and
//! contains the expected placeholder strings.

#[test]
fn x0xd_toml_template_parses_as_toml() {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    let raw = include_str!("../resources/x0xd.toml.tpl");
    // The template is intentionally comment-only (no live TOML keys) until
    // upstream x0xd exposes peer-relay TOML support. An all-comment file
    // parses as an empty table, which is valid TOML.
    let _parsed: toml::Value = toml::from_str(raw).expect("template must parse as TOML");
    // Placeholder strings must remain so the E2 substitution test can
    // assert the substitution mechanic works.
    assert!(
        raw.contains("PLACEHOLDER_NY_RELAY_AGENT_ID_HEX"),
        "NY placeholder must be present"
    );
    assert!(
        raw.contains("PLACEHOLDER_FRA_RELAY_AGENT_ID_HEX"),
        "FRA placeholder must be present"
    );
}
