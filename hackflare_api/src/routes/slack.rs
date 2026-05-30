use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode};
use serde_json::Value;

use crate::config::Config;

pub async fn slack_contact(
    State(config): State<Arc<Config>>,
    Json(body): Json<Value>,
) -> StatusCode {
    let Some(webhook_url) = &config.slack_webhook_url else {
        return StatusCode::INTERNAL_SERVER_ERROR;
    };

    let client = reqwest::Client::new();
    let res = client.post(webhook_url.clone()).json(&body).send().await;

    match res {
        Ok(r) if r.status().is_success() => StatusCode::OK,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
