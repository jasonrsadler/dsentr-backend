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
    let now = OffsetDateTime::now_utc();

    match state.db.mark_verification_token_used(&payload.token, now).await {
        Ok(Some(user_id)) => {
            if let Err(e) = state.db.set_user_verified(user_id).await {
                eprintln!("Failed to set user as verified: {:?}", e);
                return JsonResponse::server_error("Failed to update user").into_response();
            }
            JsonResponse::success("Email verified successfully").into_response()
        }
        Ok(None) => JsonResponse::bad_request("Invalid, expired, or already used token").into_response(),
        Err(_) => JsonResponse::server_error("Something went wrong").into_response(),
    }
}
