use axum::{
    extract::{Json, State},
    response::{IntoResponse, Response},
};
use rand::{distr::Alphanumeric, Rng};
extern crate serde;
use time::{OffsetDateTime, Duration};

use crate::{models::{signup::SignupPayload, user::OauthProvider}, responses::JsonResponse, state};
use crate::utils::password::hash_password;

pub async fn handle_signup(
    State(state): State<state::AppState>,
    Json(payload): Json<SignupPayload>,
) -> Response {
    let repo = &state.db;
    
    if let Ok(true) = repo.is_email_taken(&payload.email).await {
        return JsonResponse::conflict("User already registered").into_response();
    }

    let password_hash = match hash_password(&payload.password) {
        Ok(hash) => hash,
        Err(_) => return JsonResponse::server_error("Password hashing failed").into_response(),
    };

    let provider = payload
        .provider
        .as_ref()
        .copied()
        .unwrap_or(OauthProvider::Email);
    let user_id = match repo.create_user(&payload, &password_hash, provider).await {
        Ok(id) => id,
        Err(e) => {
            eprintln!("Failed to insert user: {:?}", e);
            return JsonResponse::server_error("Could not create user").into_response();
        }
    };

    let token: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let expires_at = OffsetDateTime::now_utc() + Duration::hours(24);

    if let Err(e) = repo.insert_verification_token(user_id, &token, expires_at).await {
        eprintln!("Failed to insert verification token: {:?}", e);
        return JsonResponse::server_error("Could not create verification token").into_response();
    }

    if let Err(err) = state.mailer.send_verification_email(&payload.email, &token).await {
        eprintln!("Failed to send verification email: {}", err);
        let _ = repo.cleanup_user_and_token(user_id, &token).await;
        return JsonResponse::server_error("Failed to send verification email").into_response();
    }

    JsonResponse::success("User created. Check your email to verify your account.")
        .into_response()
}