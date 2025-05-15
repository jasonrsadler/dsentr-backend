use axum::{http::header, response::IntoResponse, Json};
use crate::routes::auth::session::AuthSession;
use serde_json::json;

pub async fn dashboard_handler(AuthSession(claims): AuthSession) -> impl IntoResponse {
    let response = Json(json!({
        "message": format!("Welcome, {}", claims.email),
    }));

    (
        [
            (header::CACHE_CONTROL, "no-store, no-cache, must-revalidate"),
            (header::PRAGMA, "no-cache"),
        ],
        response,
    )
}