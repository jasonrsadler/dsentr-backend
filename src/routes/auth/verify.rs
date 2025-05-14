use axum::{
    extract::{Json, State},
    response::IntoResponse,
};
use serde::Deserialize;
use time::OffsetDateTime;
use crate::{responses::JsonResponse, state};

#[derive(Deserialize)]
pub struct VerifyEmailPayload {
    token: String,
}

pub async fn verify_email(
    State(state): State<state::AppState>,
    Json(payload): Json<VerifyEmailPayload>,
) -> impl IntoResponse {
    let pool = &state.db;

    // Try to atomically mark the token as used, only if not expired and not already used
    let now = OffsetDateTime::now_utc();
    let result = sqlx::query!(
        r#"
        UPDATE email_verification_tokens
        SET used_at = $1
        WHERE token = $2
          AND expires_at > $1
          AND used_at IS NULL
        RETURNING user_id
        "#,
        now,
        payload.token
    )
    .fetch_optional(pool)
    .await;

    match result {
        Ok(Some(record)) => {
            // Mark user as verified
            let _ = sqlx::query!(
                "UPDATE users SET is_verified = true WHERE id = $1",
                record.user_id
            )
            .execute(pool)
            .await;

            JsonResponse::success("Email verified successfully").into_response()
        }
        Ok(None) => {
            // Either invalid, expired, or already used
            JsonResponse::bad_request("Invalid, expired, or already used token").into_response()
        }
        Err(_) => JsonResponse::server_error("Something went wrong").into_response(),
    }
}