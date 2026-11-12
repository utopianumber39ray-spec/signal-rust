use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use crypto_core::{
    EncryptedMessage, IdentityKeyPair, OneTimePreKey, RatchetHeader, RatchetKeyPair,
    SignedPreKeyPublic,
};
use http_body_util::BodyExt;
use signal_server::{
    app, BundleResponse, Database, PreKeyUpload, QueuedMessage, RegistrationRequest,
    RegistrationResponse, SendMessageRequest,
};
use std::error::Error;
use tower::ServiceExt;
use uuid::Uuid;

type TestResult = Result<(), Box<dyn Error>>;
type ApiResult<T> = Result<T, Box<dyn Error>>;

struct TestUser {
    response: RegistrationResponse,
    identity: IdentityKeyPair,
    signed_prekey: RatchetKeyPair,
}

fn registration(username: &str) -> (RegistrationRequest, IdentityKeyPair, RatchetKeyPair) {
    let identity = IdentityKeyPair::generate();
    let signed = RatchetKeyPair::generate();
    let request = RegistrationRequest {
        username: username.to_owned(),
        identity: identity.public(),
        signed_prekey: SignedPreKeyPublic::new(&identity, 1, &signed),
        one_time_prekeys: (1..=2)
            .map(OneTimePreKey::generate)
            .map(|key| key.public())
            .collect(),
    };
    (request, identity, signed)
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Vec<u8>,
) -> ApiResult<(StatusCode, Vec<u8>)> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = app.clone().oneshot(builder.body(Body::from(body))?).await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes().to_vec();
    Ok((status, bytes))
}

async fn json_call<T: serde::Serialize>(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    value: &T,
) -> ApiResult<(StatusCode, Vec<u8>)> {
    call(app, method, path, token, serde_json::to_vec(value)?).await
}

async fn register(app: &Router, username: &str) -> ApiResult<TestUser> {
    let (request, identity, signed_prekey) = registration(username);
    let (status, body) = json_call(app, "POST", "/v1/users/register", None, &request).await?;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body)
    );
    Ok(TestUser {
        response: serde_json::from_slice(&body)?,
        identity,
        signed_prekey,
    })
}

async fn bundle_for(app: &Router, token: &str, username: &str) -> ApiResult<BundleResponse> {
    let (status, body) = call(
        app,
        "GET",
        &format!("/v1/users/{username}/bundle"),
        Some(token),
        Vec::new(),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    Ok(serde_json::from_slice(&body)?)
}

async fn pending_messages(app: &Router, user: &TestUser) -> ApiResult<Vec<QueuedMessage>> {
    let (status, body) = call(
        app,
        "GET",
        "/v1/messages",
        Some(&user.response.token),
        vec![],
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    Ok(serde_json::from_slice(&body)?)
}

#[tokio::test]
async fn registration_and_atomic_prekey_consumption() -> TestResult {
    let app = app(Database::in_memory().await?);
    let alice = register(&app, "alice").await?;
    register(&app, "bob").await?;
    let first = bundle_for(&app, &alice.response.token, "bob").await?;
    let second = bundle_for(&app, &alice.response.token, "bob").await?;
    assert_eq!(first.one_time_prekey.map(|key| key.id), Some(1));
    assert_eq!(second.one_time_prekey.map(|key| key.id), Some(2));
    let third = bundle_for(&app, &alice.response.token, "bob").await?;
    assert!(third.one_time_prekey.is_none());
    Ok(())
}

#[tokio::test]
async fn relays_opaque_messages_and_enforces_recipient_ack() -> TestResult {
    let app = app(Database::in_memory().await?);
    let alice = register(&app, "alice").await?;
    let bob = register(&app, "bob").await?;
    let message = EncryptedMessage {
        id: Uuid::new_v4(),
        initial: None,
        header: RatchetHeader {
            ratchet_public: [1; 32],
            previous_chain_length: 0,
            message_number: 0,
        },
        nonce: [2; 12],
        ciphertext: b"relay cannot read this".to_vec(),
    };
    let (status, _) = json_call(
        &app,
        "POST",
        "/v1/messages",
        Some(&alice.response.token),
        &SendMessageRequest {
            recipient_id: bob.response.user_id,
            message: message.clone(),
        },
    )
    .await?;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (status, _) = json_call(
        &app,
        "POST",
        "/v1/messages",
        Some(&alice.response.token),
        &SendMessageRequest {
            recipient_id: bob.response.user_id,
            message: message.clone(),
        },
    )
    .await?;
    assert_eq!(status, StatusCode::ACCEPTED);
    let mut changed = message.clone();
    changed.ciphertext.push(0);
    let (status, _) = json_call(
        &app,
        "POST",
        "/v1/messages",
        Some(&alice.response.token),
        &SendMessageRequest {
            recipient_id: bob.response.user_id,
            message: changed,
        },
    )
    .await?;
    assert_eq!(status, StatusCode::CONFLICT);
    let pending = pending_messages(&app, &bob).await?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].sender_id, alice.response.user_id);
    assert_eq!(pending[0].payload.ciphertext, message.ciphertext);
    let ack_path = format!("/v1/messages/{}/ack", message.id);
    let (status, _) = call(&app, "POST", &ack_path, Some(&alice.response.token), vec![]).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(&app, "POST", &ack_path, Some(&bob.response.token), vec![]).await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(pending_messages(&app, &bob).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn rejects_bad_tokens_duplicates_and_invalid_signatures() -> TestResult {
    let app = app(Database::in_memory().await?);
    register(&app, "alice").await?;
    let (status, _) = call(&app, "GET", "/v1/messages", Some("wrong"), vec![]).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let request = registration("alice").0;
    let (status, _) = json_call(&app, "POST", "/v1/users/register", None, &request).await?;
    assert_eq!(status, StatusCode::CONFLICT);
    let (mut request, _, _) = registration("mallory");
    request.signed_prekey.signature[0] ^= 1;
    let (status, _) = json_call(&app, "POST", "/v1/users/register", None, &request).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn prekey_rotation_selects_new_signed_key() -> TestResult {
    let app = app(Database::in_memory().await?);
    let user = register(&app, "alice").await?;
    let before = bundle_for(&app, &user.response.token, "alice").await?;
    assert_eq!(
        before.signed_prekey.public_key,
        user.signed_prekey.public_bytes()
    );
    let next = RatchetKeyPair::generate();
    let upload = PreKeyUpload {
        signed_prekey: SignedPreKeyPublic::new(&user.identity, 2, &next),
        one_time_prekeys: vec![OneTimePreKey::generate(3).public()],
    };
    let (status, _) = json_call(
        &app,
        "POST",
        "/v1/users/me/prekeys",
        Some(&user.response.token),
        &upload,
    )
    .await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let bundle = bundle_for(&app, &user.response.token, "alice").await?;
    assert_eq!(bundle.signed_prekey.id, 2);
    assert_eq!(bundle.signed_prekey.public_key, next.public_bytes());
    Ok(())
}
