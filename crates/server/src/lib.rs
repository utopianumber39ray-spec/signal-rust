#![forbid(unsafe_code)]

mod db;
mod error;
mod models;

pub use db::Database;
pub use error::{ApiError, ApiResult};
pub use models::{
    BundleResponse, ErrorResponse, PreKeyUpload, QueuedMessage, RegistrationRequest,
    RegistrationResponse, SendMessageRequest,
};

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

pub fn app(database: Database) -> axum::Router {
    axum::Router::new()
        .route("/v1/health", get(health))
        .route("/v1/users/register", post(register))
        .route("/v1/users/me/prekeys", post(prekeys))
        .route("/v1/users/:username/bundle", get(bundle))
        .route("/v1/messages", post(send_message).get(list_messages))
        .route("/v1/messages/:id/ack", post(ack))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .with_state(database)
}

async fn health() -> &'static str {
    "ok"
}

async fn register(
    State(database): State<Database>,
    Json(request): Json<RegistrationRequest>,
) -> ApiResult<(StatusCode, Json<RegistrationResponse>)> {
    let response = database.register(request).await?;
    Ok((StatusCode::CREATED, Json(response)))
}

async fn prekeys(
    State(database): State<Database>,
    headers: HeaderMap,
    Json(upload): Json<PreKeyUpload>,
) -> ApiResult<StatusCode> {
    let user_id = authenticate(&headers, &database).await?;
    database.upload_prekeys(user_id, upload).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn bundle(
    State(database): State<Database>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> ApiResult<Json<BundleResponse>> {
    authenticate(&headers, &database).await?;
    Ok(Json(database.bundle_for(&username).await?))
}

async fn send_message(
    State(database): State<Database>,
    headers: HeaderMap,
    Json(request): Json<SendMessageRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let sender_id = authenticate(&headers, &database).await?;
    let id = database
        .enqueue(sender_id, request.recipient_id, request.message)
        .await?;
    Ok((StatusCode::ACCEPTED, Json(serde_json::json!({"id": id}))))
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    limit: Option<i64>,
}

async fn list_messages(
    State(database): State<Database>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<Vec<QueuedMessage>>> {
    let user_id = authenticate(&headers, &database).await?;
    Ok(Json(
        database
            .pending_messages(user_id, query.limit.unwrap_or(100))
            .await?,
    ))
}

async fn ack(
    State(database): State<Database>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let user_id = authenticate(&headers, &database).await?;
    if database.acknowledge(user_id, id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

async fn authenticate(headers: &HeaderMap, database: &Database) -> ApiResult<Uuid> {
    let authorization = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or(ApiError::Unauthorized)?;
    let value = authorization.to_str().map_err(|_| ApiError::Unauthorized)?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or(ApiError::Unauthorized)?;
    database.authenticate(token).await
}

pub async fn serve(listener: tokio::net::TcpListener, database: Database) -> std::io::Result<()> {
    axum::serve(listener, app(database))
        .await
        .map_err(std::io::Error::other)
}
