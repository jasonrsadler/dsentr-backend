use axum::{
    extract::{Json, State},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use time::{OffsetDateTime, Duration};
use uuid::Uuid;

use crate::{
    responses::JsonResponse,
    state::AppState
};

#[derive(Deserialize)]
pub struct ForgotPasswordRequest {
    email: String,
}

pub async fn handle_forgot_password(
    State(state): State<AppState>,
    Json(payload): Json<ForgotPasswordRequest>,
) -> Response {
    let db = &state.db;
    let mailer = &state.mailer;
    let email = payload.email.trim();

    if let Ok(Some(user)) = sqlx::query!("SELECT id FROM users WHERE email = $1", email)
    .fetch_optional(db)
    .await
    {
        let token = Uuid::new_v4().to_string();
        let expiry = OffsetDateTime::now_utc() + Duration::minutes(30);

        let insert_result = sqlx::query!(
            "INSERT INTO password_resets (user_id, token, expires_at)
            VALUES ($1, $2, $3)",
            user.id,
            token,
            expiry
        )
        .execute(db)
        .await;

        if let Err(e) = insert_result {
            eprintln!("Failed to insert password reset token: {:?}", e);
        } else if let Err(e) = mailer.send_reset_email(email, &token).await {
            eprintln!("Failed to send reset email: {:?}", e);
        }
    }


    // Always respond with generic success
    JsonResponse::success("If that email exists, a reset link has been sent.")
        .into_response()
}
