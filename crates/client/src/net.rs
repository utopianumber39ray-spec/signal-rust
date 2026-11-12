use crate::{ClientError, Result};
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

pub(crate) async fn request_json<T: DeserializeOwned, B: Serialize>(
    http: &reqwest::Client,
    server: &str,
    token: Option<&str>,
    method: Method,
    path: &str,
    body: Option<&B>,
) -> Result<T> {
    let mut request = http.request(method, format!("{server}{path}"));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    if let Some(body) = body {
        request = request.json(body);
    }
    let mut response = request.send().await?;
    let status = response.status();
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(ClientError::InvalidInput(
                "server response exceeded one MiB".to_owned(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        let message = serde_json::from_slice::<signal_server::ErrorResponse>(&bytes)
            .map(|body| body.error)
            .unwrap_or_else(|_| String::from_utf8_lossy(&bytes).into_owned());
        let message: String = message
            .chars()
            .map(|character| {
                if character.is_control() && !character.is_whitespace() {
                    ' '
                } else {
                    character
                }
            })
            .take(512)
            .collect();
        return Err(ClientError::Server {
            status: status.as_u16(),
            message,
        });
    }
    if status == StatusCode::NO_CONTENT || bytes.is_empty() {
        return serde_json::from_slice(b"null").map_err(ClientError::from);
    }
    serde_json::from_slice(&bytes).map_err(ClientError::from)
}

pub(crate) fn http_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(20))
        .build()?)
}

pub(crate) async fn post_unauthenticated<T: DeserializeOwned, B: Serialize>(
    server: &str,
    path: &str,
    body: &B,
) -> Result<T> {
    let http = http_client()?;
    request_json(&http, server, None, Method::POST, path, Some(body)).await
}
