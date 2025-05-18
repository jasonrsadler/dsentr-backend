use axum::{
    extract::{Json, Path, State},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;
use crate::{state::AppState, responses::JsonResponse};
use time::OffsetDateTime;
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    token: String,
    password: String,
}

// 👇 Used by both handlers
pub async fn verify_password_reset_token(
    db: &PgPool,
    token: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    let result = sqlx::query!(
        "SELECT user_id FROM password_resets
         WHERE token = $1 AND expires_at > $2 AND used_at IS NULL",
        token,
        OffsetDateTime::now_utc()
    )
    .fetch_optional(db)
    .await?;

    Ok(result.map(|r| r.user_id))
}

// 👇 Called on page load (GET request)
pub async fn handle_verify_token(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Response {
    let db = &state.db;
    match verify_password_reset_token(db, token.trim()).await {
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
    let db = &state.db;
    let token = payload.token.trim();
    let new_password = payload.password.trim();

    let user_id = match verify_password_reset_token(db, token).await {
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
    if let Err(e) = sqlx::query!(
        "UPDATE users SET password_hash = $1 WHERE id = $2",
        password_hash,
        user_id
    )
    .execute(db)
    .await
    {
        eprintln!("Error updating password: {:?}", e);
        return JsonResponse::server_error("Internal server error").into_response();
    }

    // Mark token as used
    if let Err(e) = sqlx::query!(
        "UPDATE password_resets SET used_at = $1 WHERE token = $2",
        OffsetDateTime::now_utc(),
        token
    )
    .execute(db)
    .await
    {
        eprintln!("Error marking token used: {:?}", e);
        return JsonResponse::server_error("Internal server error").into_response();
    }

    JsonResponse::success("Password has been reset.").into_response()
}
