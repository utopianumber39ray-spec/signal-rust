use crate::models::ErrorResponse;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use thiserror::Error;

pub type ApiResult<T> = std::result::Result<T, ApiError>;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("authentication required")]
    Unauthorized,
    #[error("not found")]
    NotFound,
    #[error("resource already exists")]
    Conflict,
    #[error("request body too large")]
    PayloadTooLarge,
    #[error("serialization failed")]
    Serialization(#[from] serde_json::Error),
    #[error("database error")]
    Database(#[from] sqlx::Error),
    #[error("internal error")]
    Internal(String),
}

impl ApiError {
    pub fn from_sqlx(error: sqlx::Error, _conflict_message: &str) -> Self {
        if error.to_string().contains("UNIQUE constraint failed") {
            Self::Conflict
        } else {
            Self::Internal(error.to_string())
        }
    }

    pub fn database(error: sqlx::Error) -> Self {
        Self::Internal(error.to_string())
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict => StatusCode::CONFLICT,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Serialization(_) | Self::Database(_) | Self::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    fn public_message(&self) -> String {
        match self {
            Self::BadRequest(message) => message.clone(),
            Self::Internal(_) => "internal server error".to_owned(),
            other => other.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let message = match &self {
            Self::Database(error) => {
                eprintln!("database error: {error}");
                self.public_message()
            }
            Self::Serialization(error) => {
                eprintln!("serialization error: {error}");
                self.public_message()
            }
            other => other.public_message(),
        };
        (status, Json(ErrorResponse { error: message })).into_response()
    }
}
