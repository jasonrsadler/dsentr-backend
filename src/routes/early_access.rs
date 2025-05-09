use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use sqlx::PgPool;

#[derive(Deserialize)]
pub struct EarlyAccessPayload {
    pub email: String,
}

pub async fn handle_early_access(
    State(pool): State<PgPool>,
    Json(payload): Json<EarlyAccessPayload>,
) -> impl IntoResponse {
    let result = sqlx::query("INSERT INTO early_access_emails (email) VALUES ($1)")
        .bind(&payload.email)
        .execute(&pool)
        .await;

    match result {
        Ok(_) => (StatusCode::OK, "Thanks for signing up!"),
        Err(e) => {
            eprintln!("DB insert error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong")
        }
    }
}
