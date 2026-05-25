//! Integration tests for the REST client surface — drive every typed
//! endpoint against a `wiremock` mock daemon. Verifies request shape
//! (method, path, auth header, body), response decoding, and error
//! mapping in one pass.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

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
    Mock::given(method("POST"))
        .and(path("/agent/card/import"))
        .and(body_partial_json(json!({
            "card": {"agent_id": me.0, "display_name": "Alice"}
        })))
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
    let list = client_against(&server).await.contacts().list().await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].trust_level, TrustLevel::Trusted);
    assert_eq!(list[0].label.as_deref(), Some("Bob"));
    assert_eq!(list[0].added_at, Some(1_779_739_867));
}

#[tokio::test]
async fn contacts_set_trust_posts_to_quick_endpoint() {
    let server = MockServer::start().await;
    let peer = id('c');
    Mock::given(method("POST"))
        .and(path("/contacts/trust"))
        .and(body_partial_json(json!({
            "agent_id": peer.0,
            "trust_level": "blocked"
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

#[tokio::test]
async fn dm_send_returns_message_id() {
    let server = MockServer::start().await;
    let peer = id('e');
    Mock::given(method("POST"))
        .and(path("/direct/send"))
        .and(body_partial_json(json!({"agent_id": peer.0})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"message_id": "m-42"})))
        .mount(&server)
        .await;
    let id = client_against(&server)
        .await
        .messages()
        .send(&peer, "hello", "Alice")
        .await
        .unwrap();
    assert_eq!(id.as_deref(), Some("m-42"));
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
    Mock::given(method("POST"))
        .and(path("/groups"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "group_id": "g-1", "name": "Team", "member_count": 1, "is_owner": true
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/groups/g-1/invite"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"invite": "x0x://invite/zzz"})))
        .mount(&server)
        .await;
    let c = client_against(&server).await;
    let group = c.groups().create("Team", Some("Alice")).await.unwrap();
    assert_eq!(group.group_id.0, "g-1");
    assert!(group.is_owner);
    let invite = c.groups().invite(&group.group_id).await.unwrap();
    assert_eq!(invite.0, "x0x://invite/zzz");
}

#[tokio::test]
async fn groups_join_returns_group() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/groups/join"))
        .and(body_partial_json(json!({"invite": "x0x://invite/zzz"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "group_id": "g-2", "name": "External"
        })))
        .mount(&server)
        .await;
    let g = client_against(&server)
        .await
        .groups()
        .join(&GroupInvite("x0x://invite/zzz".into()), None)
        .await
        .unwrap();
    assert_eq!(g.group_id, GroupId("g-2".into()));
}

#[tokio::test]
async fn groups_send_returns_id() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/groups/g-1/send"))
        .and(body_partial_json(json!({"body": "team msg", "kind": "chat"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"message_id": "gm-1"})))
        .mount(&server)
        .await;
    let id = client_against(&server)
        .await
        .groups()
        .send(&GroupId("g-1".into()), "team msg")
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
    let online = client_against(&server).await.presence().online().await.unwrap();
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
