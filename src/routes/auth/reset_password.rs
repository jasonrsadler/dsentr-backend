use axum::{
    extract::{Json, Path, State},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use crate::{state::AppState, responses::JsonResponse};
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    token: String,
    password: String,
}

// 👇 Called on page load (GET request)
pub async fn handle_verify_token(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Response {
    match state.db.verify_password_reset_token(&token).await {
        Ok(Some(_user_id)) => JsonResponse::success("Token is valid.").into_response(),
        Ok(None) => JsonResponse::server_error("Invalid or expired token.").into_response(),
        Err(e) => {
            eprintln!("DB error verifying token: {:?}", e);
            JsonResponse::server_error("Internal server error").into_response()
        }
    }

}

// 👇 Called on form submission (POST request)
pub async fn handle_reset_password(
    State(state): State<AppState>,
    Json(payload): Json<ResetPasswordRequest>,
) -> Response {
    let token = payload.token.trim();
    let new_password = payload.password.trim();

    let user_id = match state.db.verify_password_reset_token(token).await {
        Ok(Some(id)) => id,
        Ok(None) => return JsonResponse::server_error("Invalid or expired token.").into_response(),
        Err(e) => {
            eprintln!("Error verifying token: {:?}", e);
            return JsonResponse::server_error("Internal server error").into_response();
        }
    };

    // Hash password
    let salt = SaltString::generate(&mut rand_core::OsRng);
    let password_hash = match Argon2::default()
        .hash_password(new_password.as_bytes(), &salt)
    {
        Ok(hash) => hash.to_string(),
        Err(e) => {
            eprintln!("Password hashing failed: {:?}", e);
            return JsonResponse::server_error("Internal server error").into_response();
        }
    };

    // Update password
    if let Err(e) = state.db.update_user_password(user_id, &password_hash).await {
        eprintln!("Error updating password: {:?}", e);
        return JsonResponse::server_error("Internal server error").into_response();
    }

    // Mark token as used
    if let Err(e) = state.db.mark_password_reset_token_used(token).await {
        eprintln!("Error marking token used: {:?}", e);
        return JsonResponse::server_error("Internal server error").into_response();
    }

    JsonResponse::success("Password has been reset.").into_response()
}
