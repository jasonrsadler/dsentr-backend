use core::fmt;

use axum::{
    extract::{Json, State},
    response::{IntoResponse, Response},
};
use rand::{distr::Alphanumeric, Rng};
extern crate serde;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use time::{OffsetDateTime, Duration};

use crate::{responses::JsonResponse, state};
use crate::utils::password::hash_password;

#[derive(sqlx::Type, Debug, Deserialize, Serialize)]
#[sqlx(type_name = "oauth_provider", rename_all = "lowercase")] // match your PostgreSQL type
#[serde(rename_all = "lowercase")] // <- Ensures it matches JSON like "google"
pub enum OauthProvider {
    Google,
    Github,
    Apple,
    Email
}

impl fmt::Display for OauthProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            OauthProvider::Google => "Google",
            OauthProvider::Github => "GitHub",
            OauthProvider::Apple => "Apple",
            OauthProvider::Email => "Email"
        };
        write!(f, "{}", s)
    }
}

#[derive(Deserialize)]
pub struct SignupPayload {
    pub email: String,
    pub password: String,
    pub first_name: String,
    pub last_name: String,
    pub company_name: Option<String>,
    pub country: Option<String>,
    pub tax_id: Option<String>,
    #[serde(default)]
    pub provider: Option<OauthProvider>
}

pub async fn handle_signup(
    State(state): State<state::AppState>,
    Json(payload): Json<SignupPayload>,
) -> Response {
    // Check if email already exists
    let pool = &state.db;
    let existing_user: Result<Option<Option<i32>>, sqlx::Error> = sqlx::query_scalar!(
        "SELECT 1 FROM users WHERE email = $1",
        payload.email
    )
    .fetch_optional(pool)
    .await;

    match existing_user {
        Ok(Some(_)) => {
            return JsonResponse::conflict("User already registered").into_response();
        }
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
            return JsonResponse::conflict("Email already in use").into_response();
        }
        Err(e) => {
            eprintln!("DB error: {:?}", e);
            return JsonResponse::server_error("Database error").into_response();
        }
        _ => {}
    }

    // Hash password
    let password_hash = match hash_password(&payload.password) {
        Ok(hash) => hash,
        Err(_) => return JsonResponse::server_error("Password hashing failed").into_response(),
    };

    let provider = payload.provider.unwrap_or(OauthProvider::Email);

    // Insert user and get ID
    let user_id_result = sqlx::query_scalar!(
        r#"
        INSERT INTO users (
            email, password_hash, first_name, last_name, company_name, country, tax_id,
            is_verified, is_subscribed, settings, created_at, updated_at, oauth_provider
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            false, false, '{}', now(), now(), $8::oauth_provider
        )
        RETURNING id
        "#,
        payload.email,
        password_hash,
        payload.first_name,
        payload.last_name,
        payload.company_name,
        payload.country,
        payload.tax_id,
        provider as OauthProvider
    )
    .fetch_one(pool)
    .await;

    let user_id: Uuid = match user_id_result {
        Ok(id) => id,
        Err(e) => {
            eprintln!("Failed to insert user: {:?}", e);
            return JsonResponse::server_error("Could not create user").into_response();
        }
    };

    // Generate token
    let token: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let expires_at = OffsetDateTime::now_utc() + Duration::hours(24);

    // Store token
    let token_result = sqlx::query!(
        r#"
        INSERT INTO email_verification_tokens (user_id, token, expires_at)
        VALUES ($1, $2, $3)
        "#,
        user_id,
        token,
        expires_at
    )
    .execute(pool)
    .await;

    if let Err(e) = token_result {
        eprintln!("Failed to insert verification token: {:?}", e);
        return JsonResponse::server_error("Could not create verification token").into_response();
    }

    

    if let Err(err) = state.mailer.send_verification_email(&payload.email, &token).await {
        eprintln!("Failed to send verification email: {}", err);

        // Optional cleanup: delete user and token if email fails
        let _ = sqlx::query!(
            "DELETE FROM email_verification_tokens WHERE token = $1",
            token
        )
        .execute(pool)
        .await;

        let _ = sqlx::query!(
            "DELETE FROM users WHERE id = $1",
            user_id
        )
        .execute(pool)
        .await;

        return JsonResponse::server_error("Failed to send verification email").into_response();
    }

    JsonResponse::success("User created. Check your email to verify your account.")
        .into_response()
}
