use axum::{
    extract::{Json, State},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use time::{OffsetDateTime, Duration};
use uuid::Uuid;

use crate::{
    responses::JsonResponse,
    state::AppState,
};

#[derive(Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

pub async fn handle_forgot_password(
    State(state): State<AppState>,
    Json(payload): Json<ForgotPasswordRequest>,
) -> Response {
    let db = &state.db;
    let mailer = &state.mailer;
    let email = payload.email.trim();

    // Handle Result first
    match db.find_user_id_by_email(email).await {
        Ok(Some(user_id)) => {
            let token = Uuid::new_v4().to_string();
            let expiry = OffsetDateTime::now_utc() + Duration::minutes(30);

            if let Err(e) = db.insert_password_reset_token(user_id.id, &token, expiry).await {
                eprintln!("Failed to insert password reset token: {:?}", e);
            } else if let Err(e) = mailer.send_reset_email(email, &token).await {
                eprintln!("Failed to send reset email: {:?}", e);
            }
        }
        Ok(None) => {
            // Email not found — silently ignore
        }
        Err(e) => {
            eprintln!("Error looking up user by email: {:?}", e);
            // Still fall through to generic response
        }
    }

    JsonResponse::success("If that email exists, a reset link has been sent.")
        .into_response()
}
