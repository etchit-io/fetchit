//! Integration tests for the REST client surface — drive every typed
//! endpoint against a `wiremock` mock daemon. Verifies request shape
//! (method, path, auth header, body), response decoding, and error
//! mapping in one pass.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use fetchit_chat::contacts::TrustLevel;
use fetchit_chat::groups::{GroupId, GroupInvite};
use fetchit_chat::identity::{AgentCard, AgentId};
use fetchit_chat::{ChatError, Client};
use serde_json::json;
use wiremock::matchers::{bearer_token, body_partial_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOK: &str = "test-token";

async fn client_against(server: &MockServer) -> Client {
    Client::builder()
        .base_url(server.uri())
        .token(TOK)
        .build()
        .await
        .unwrap()
}

fn id(prefix: char) -> AgentId {
    AgentId::parse(prefix.to_string().repeat(64)).unwrap()
}

#[tokio::test]
async fn health_succeeds_on_200() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/health"))
        .and(bearer_token(TOK))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&server)
        .await;
    client_against(&server).await.health().await.unwrap();
}

#[tokio::test]
async fn identity_me_decodes() {
    let server = MockServer::start().await;
    let me = id('a');
    Mock::given(method("GET"))
        .and(path("/agent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "agent_id": me.0,
            "machine_id": "machine-1",
            "user_id": null,
        })))
        .mount(&server)
        .await;
    let identity = client_against(&server).await.identity().me().await.unwrap();
    assert_eq!(identity.agent_id, me);
    assert_eq!(identity.machine_id, "machine-1");
    assert!(identity.user_id.is_none());
}

#[tokio::test]
async fn identity_card_returns_structured() {
    let server = MockServer::start().await;
    let me = id('a');
    Mock::given(method("GET"))
        .and(path("/agent/card"))
        .and(query_param("display_name", "Alice"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "card": {
                "agent_id": me.0,
                "display_name": "Alice",
                "created_at": 1_779_740_234,
                "addresses": ["1.2.3.4:5483"]
            }
        })))
        .mount(&server)
        .await;
    let card = client_against(&server)
        .await
        .identity()
        .card("Alice")
        .await
        .unwrap();
    assert_eq!(card.display_name, "Alice");
    assert_eq!(card.agent_id, me);
    assert_eq!(card.addresses, vec!["1.2.3.4:5483".to_string()]);
}

#[tokio::test]
async fn identity_import_posts_card_to_correct_path() {
    let server = MockServer::start().await;
    let me = id('a');
    // x0xd's `/agent/card/import` expects `card` to be the
    // `x0x://agent/...` URI as a string (not the decoded object).
    Mock::given(method("POST"))
        .and(path("/agent/card/import"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    let card = AgentCard {
        agent_id: me,
        display_name: "Alice".into(),
        created_at: None,
        addresses: vec![],
        extra: serde_json::Value::Null,
    };
    client_against(&server)
        .await
        .identity()
        .import(&card)
        .await
        .unwrap();
    // Assert x0xd was actually called with a string-form card field.
    let req = &server.received_requests().await.unwrap()[0];
    let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
    let card_field = body
        .get("card")
        .and_then(|v| v.as_str())
        .expect("card field must be a string, not an object");
    assert!(
        card_field.starts_with("x0x://agent/"),
        "card field must be a share URI, got: {card_field}"
    );
}

#[tokio::test]
async fn contacts_list_decodes() {
    let server = MockServer::start().await;
    let peer = id('b');
    Mock::given(method("GET"))
        .and(path("/contacts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "contacts": [
                {"agent_id": peer.0, "trust_level": "trusted", "label": "Bob", "added_at": 1_779_739_867}
            ]
        })))
        .mount(&server)
        .await;
    let list = client_against(&server)
        .await
        .contacts()
        .list()
        .await
        .unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].trust_level, TrustLevel::Trusted);
    assert_eq!(list[0].label.as_deref(), Some("Bob"));
    assert_eq!(list[0].added_at, Some(1_779_739_867));
}

#[tokio::test]
async fn contacts_set_trust_posts_to_quick_endpoint() {
    let server = MockServer::start().await;
    let peer = id('c');
    // The daemon's quick-set route expects `level`, not `trust_level`.
    // Older versions of this test asserted the wrong shape, which let
    // a 422-silently-eaten regression through.
    Mock::given(method("POST"))
        .and(path("/contacts/trust"))
        .and(body_partial_json(json!({
            "agent_id": peer.0,
            "level": "blocked"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    client_against(&server)
        .await
        .contacts()
        .set_trust(&peer, TrustLevel::Blocked)
        .await
        .unwrap();

    // Confirm the body really uses `level` — wiremock's
    // body_partial_json above passes if either matches, since absent
    // fields are ignored. Inspect the captured request to be sure.
    let req = &server.received_requests().await.unwrap()[0];
    let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(body["level"], "blocked");
    assert!(body.get("trust_level").is_none());
}

#[tokio::test]
async fn contacts_remove_uses_delete() {
    let server = MockServer::start().await;
    let peer = id('d');
    Mock::given(method("DELETE"))
        .and(path(format!("/contacts/{}", peer.0)))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    client_against(&server)
        .await
        .contacts()
        .remove(&peer)
        .await
        .unwrap();
}

/// With no relay (or other transport) wired, `send` surfaces a
/// `NoTransportAvailable` error rather than falling back to x0xd's
/// `/direct/send`. The chat layer is relay-routed.
#[tokio::test]
async fn dm_send_without_relay_transport_errors_with_no_transport() {
    let server = MockServer::start().await;
    let peer = id('e');
    let err = client_against(&server)
        .await
        .messages()
        .send(&peer, "hello", "Alice")
        .await
        .unwrap_err();
    assert!(matches!(err, fetchit_chat::ChatError::NoTransportAvailable));
}

/// Inbound transport bytes (JSON envelope `{text, sender_name, ts}`)
/// decode back into a `DirectMessage` with the original fields. This
/// is the inverse of what the chat layer puts on the wire when
/// sending — round-trip parity guard.
#[tokio::test]
async fn relay_inbound_payload_round_trips_to_direct_message() {
    use fetchit_chat::messages::decode_direct_message;
    use fetchit_chat::transport::{InboundEnvelope, OutboundKind};
    let payload = serde_json::to_vec(&serde_json::json!({
        "text": "hi there",
        "sender_name": "Alice",
        "ts": 1_700_000_000_000_u64,
    }))
    .unwrap();
    let inbound = InboundEnvelope {
        kind: OutboundKind::Dm,
        from: id('e'),
        payload,
        timestamp_ms: 1_700_000_000_000,
        transport_name: "relay",
        transit: None,
    };
    let dm = decode_direct_message(inbound).unwrap();
    assert_eq!(dm.body, "hi there");
    assert_eq!(dm.sender_name.as_deref(), Some("Alice"));
    assert_eq!(dm.timestamp_ms, Some(1_700_000_000_000));
}

#[tokio::test]
async fn legacy_x0xd_dm_send_path_is_removed() {
    // Documentation-by-test: posts to `/direct/send` no longer fire.
    // The chat layer routes via the message Router. If a future change
    // re-introduces the x0xd send path, this assertion gates the regression.
    let server = MockServer::start().await;
    let peer = id('e');
    Mock::given(method("POST"))
        .and(path("/direct/send"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"message_id": "m-1"})))
        .mount(&server)
        .await;
    let _ = client_against(&server)
        .await
        .messages()
        .send(&peer, "hi there", "Alice")
        .await;
    let requests = server.received_requests().await.unwrap();
    let direct_send_count = requests
        .iter()
        .filter(|r| r.url.path() == "/direct/send")
        .count();
    assert_eq!(direct_send_count, 0);
}

#[tokio::test]
async fn dm_connect_posts_to_agents_connect() {
    let server = MockServer::start().await;
    let peer = id('f');
    Mock::given(method("POST"))
        .and(path("/agents/connect"))
        .and(body_partial_json(json!({"agent_id": peer.0})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    client_against(&server)
        .await
        .messages()
        .connect(&peer)
        .await
        .unwrap();
}

#[tokio::test]
async fn groups_create_and_invite() {
    let server = MockServer::start().await;
    // The daemon only accepts plaintext sends on `public_open` groups,
    // so fetchit-chat always sends that preset on create.
    Mock::given(method("POST"))
        .and(path("/groups"))
        .and(body_partial_json(json!({
            "name": "Team",
            "display_name": "Alice",
            "preset": "public_open"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "group_id": "g-1", "name": "Team", "member_count": 1, "is_owner": true
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/groups/g-1/invite"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"invite_link": "x0x://invite/zzz"})),
        )
        .mount(&server)
        .await;
    let c = client_against(&server).await;
    let group = c.groups().create("Team", Some("Alice")).await.unwrap();
    assert_eq!(group.group_id.as_str(), "g-1");
    assert!(group.is_owner);
    let invite = c.groups().invite(&group.group_id).await.unwrap();
    assert_eq!(invite.0, "x0x://invite/zzz");
}

#[tokio::test]
async fn groups_join_waits_for_membership_then_returns_group() {
    let server = MockServer::start().await;
    let me = id('a');
    Mock::given(method("POST"))
        .and(path("/groups/join"))
        .and(body_partial_json(json!({"invite": "x0x://invite/zzz"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "group_id": "g-2", "name": "External"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/agent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "agent_id": me.0,
            "machine_id": "m-1",
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/groups/g-2/members"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "members": [{"agent_id": me.0, "state": "active"}]
        })))
        .mount(&server)
        .await;
    let g = client_against(&server)
        .await
        .groups()
        .join(&GroupInvite("x0x://invite/zzz".into()), None)
        .await
        .unwrap();
    assert_eq!(g.group_id, GroupId::parse("g-2").unwrap());
}

#[tokio::test]
async fn groups_join_polls_members_until_self_appears_active() {
    let server = MockServer::start().await;
    let me = id('a');
    Mock::given(method("POST"))
        .and(path("/groups/join"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "group_id": "g-conv", "name": "Converging"
        })))
        .mount(&server)
        .await;
    // First two /members polls show only a different member, then the
    // joiner appears active. join() must keep polling and not surface
    // a converged group until that point.
    Mock::given(method("GET"))
        .and(path("/groups/g-conv/members"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "members": [{"agent_id": id('b').0, "state": "active"}]
        })))
        .up_to_n_times(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/groups/g-conv/members"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "members": [
                {"agent_id": id('b').0, "state": "active"},
                {"agent_id": me.0, "state": "active"}
            ]
        })))
        .mount(&server)
        .await;
    let g = client_against(&server)
        .await
        .groups()
        .join_with_membership_wait(
            &GroupInvite("x0x://invite/conv".into()),
            None,
            &me,
            Duration::from_secs(2),
            Duration::from_millis(20),
        )
        .await
        .unwrap();
    assert_eq!(g.group_id, GroupId::parse("g-conv").unwrap());
}

#[tokio::test]
async fn groups_join_surfaces_joiner_not_converged_on_timeout() {
    let server = MockServer::start().await;
    let me = id('a');
    Mock::given(method("POST"))
        .and(path("/groups/join"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "group_id": "g-slow", "name": "Slow"
        })))
        .mount(&server)
        .await;
    // Joiner never appears active; only a non-self member is ever
    // returned. join_with_membership_wait must surface
    // JoinerNotConverged once the timeout elapses.
    Mock::given(method("GET"))
        .and(path("/groups/g-slow/members"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "members": [{"agent_id": id('b').0, "state": "active"}]
        })))
        .mount(&server)
        .await;
    let err = client_against(&server)
        .await
        .groups()
        .join_with_membership_wait(
            &GroupInvite("x0x://invite/slow".into()),
            None,
            &me,
            Duration::from_millis(120),
            Duration::from_millis(20),
        )
        .await
        .unwrap_err();
    match err {
        ChatError::JoinerNotConverged {
            group_id,
            waited_ms,
        } => {
            assert_eq!(group_id, "g-slow");
            assert_eq!(waited_ms, 120);
        }
        other => panic!("expected JoinerNotConverged, got {other:?}"),
    }
}

#[tokio::test]
async fn groups_join_surfaces_underlying_error_when_members_keeps_erroring() {
    let server = MockServer::start().await;
    let me = id('a');
    Mock::given(method("POST"))
        .and(path("/groups/join"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "group_id": "g-err", "name": "ErrLoop"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/groups/g-err/members"))
        .respond_with(ResponseTemplate::new(503).set_body_string("daemon down"))
        .mount(&server)
        .await;
    let err = client_against(&server)
        .await
        .groups()
        .join_with_membership_wait(
            &GroupInvite("x0x://invite/err".into()),
            None,
            &me,
            Duration::from_millis(120),
            Duration::from_millis(20),
        )
        .await
        .unwrap_err();
    match err {
        ChatError::Daemon { status, .. } => assert_eq!(status, 503),
        other => panic!("expected Daemon(503), got {other:?}"),
    }
}

#[tokio::test]
async fn groups_send_returns_id() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/groups/g-1/send"))
        .and(body_partial_json(
            json!({"body": "team msg", "kind": "chat"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"message_id": "gm-1"})))
        .mount(&server)
        .await;
    let id = client_against(&server)
        .await
        .groups()
        .send(&GroupId::parse("g-1").unwrap(), "team msg")
        .await
        .unwrap();
    assert_eq!(id.as_deref(), Some("gm-1"));
}

#[tokio::test]
async fn presence_online_decodes() {
    let server = MockServer::start().await;
    let peer = id('1');
    Mock::given(method("GET"))
        .and(path("/presence/online"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "agents": [
                {"agent_id": peer.0, "last_seen": 1_779_740_232, "addresses": ["1.2.3.4:5483"]}
            ]
        })))
        .mount(&server)
        .await;
    let online = client_against(&server)
        .await
        .presence()
        .online()
        .await
        .unwrap();
    assert_eq!(online.len(), 1);
    assert_eq!(online[0].last_seen, Some(1_779_740_232));
}

#[tokio::test]
async fn auth_header_is_attached() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/agent"))
        .and(header("authorization", format!("Bearer {TOK}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "agent_id": "a".repeat(64), "machine_id": "m"
        })))
        .mount(&server)
        .await;
    client_against(&server).await.identity().me().await.unwrap();
}

#[tokio::test]
async fn non_2xx_maps_to_daemon_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/agent"))
        .respond_with(ResponseTemplate::new(401).set_body_string("nope"))
        .mount(&server)
        .await;
    let err = client_against(&server)
        .await
        .identity()
        .me()
        .await
        .unwrap_err();
    match err {
        ChatError::Daemon { status, body } => {
            assert_eq!(status, 401);
            assert!(body.contains("nope"));
        }
        other => panic!("expected daemon error, got {other:?}"),
    }
}
