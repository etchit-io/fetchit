//! Verifies the bundled x0xd TOML template is syntactically valid and
//! carries the expected peer-relay structure.

#[test]
fn x0xd_toml_template_parses_as_toml() {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    let raw = include_str!("../resources/x0xd.toml.tpl");
    let parsed: toml::Value = toml::from_str(raw).expect("template must parse as TOML");
    let pr = &parsed["peer_relay"];
    assert_eq!(pr["enabled"].as_bool(), Some(true));
    assert!(pr["candidates"].as_array().unwrap().len() >= 2);
}
