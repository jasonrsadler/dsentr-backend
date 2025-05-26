use axum::{
    extract::{Json, State},
    response::{IntoResponse, Response},
    http::{header, HeaderMap, HeaderValue, StatusCode},
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use serde_json::{json, to_value};
use uuid::Uuid;
use crate::{models::user::{PublicUser, User}, responses::JsonResponse, state::AppState, utils::{jwt::create_jwt, password::verify_password}};
use crate::routes::auth::claims::Claims;
use serde::Deserialize;
use chrono::{Utc, Duration};
use time::Duration as TimeDuration;

use super::session::AuthSession;

#[derive(Deserialize)]
pub struct LoginPayload {
    pub email: String,
    pub password: String,
    pub remember: bool,
}

pub async fn handle_login(
    State(app_state): State<AppState>,
    Json(payload): Json<LoginPayload>,
) -> Response {
    let pool = &app_state.db;

let user = sqlx::query_as::<_, User>(
    "SELECT id, email, password_hash, first_name, last_name, role, plan, oauth_provider, company_name FROM users WHERE email = $1"
)
.bind(&payload.email)
.fetch_optional(pool)
.await;

    let user = match user {
        Ok(Some(record)) => record,
        Ok(None) => return JsonResponse::unauthorized("Invalid credentials").into_response(),
        Err(e) => {
            eprintln!("DB error: {:?}", e);
            return JsonResponse::server_error("Database error").into_response();
        }
    };

    if user.password_hash.trim().is_empty() {
        let provider = user.oauth_provider;
        let provider_name = provider
            .map(|p| p.to_string())
            .unwrap_or("an OAuth provider".to_string());
        return JsonResponse::unauthorized(&format!(
            "This account was created with {} login. Please use that provider to sign in.",
            provider_name
        )).into_response();
    }
    match verify_password(&payload.password, &user.password_hash) {
        Ok(true) => {
            let expires_in = if payload.remember {
                Duration::days(30)
            } else {
                Duration::days(7)
            };

            let claims = Claims {
                id: user.id.to_string(),
                email: user.email.clone(),
                exp: (Utc::now() + expires_in).timestamp() as usize,
                first_name: user.first_name.clone(),
                last_name: user.last_name.clone(),
                role: user.role,
                plan: user.plan.clone(),
                company_name: user.company_name.clone()
            };

            match create_jwt(&claims) {
                Ok(token) => {
                    let cookie = Cookie::build(("auth_token", token))
                        .http_only(true)
                        .secure(false)
                        .same_site(SameSite::Lax)
                        .path("/")
                        .max_age(TimeDuration::seconds(expires_in.num_seconds()))
                        .build();

                    let mut headers = HeaderMap::new();
                    headers.insert(
                        header::SET_COOKIE,
                        HeaderValue::from_str(&cookie.to_string()).unwrap(),
                    );
                    let user_json = to_value(&user).expect("User serialization failed");
                    (
                        StatusCode::OK,
                        headers,
                        Json(json!({
                            "success": true,
                            "user": user_json
                        })),
                    ).into_response()
                }
                Err(e) => {
                    eprintln!("JWT error: {:?}", e);
                    JsonResponse::server_error("Token generation failed").into_response()
                }
            }
        }
        Ok(false) => JsonResponse::unauthorized("Invalid credentials").into_response(),
        Err(e) => {
            eprintln!("Password verification error: {:?}", e);
            JsonResponse::server_error("Internal error").into_response()
        }
    }
}

pub async fn handle_me(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
) -> Response {
    let pool = &app_state.db;
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    let user = sqlx::query_as::<_, PublicUser>(
        "SELECT id, email, first_name, last_name, role, plan, company_name FROM users WHERE id = $1"
    )
    .bind(&user_id)
    .fetch_optional(pool)
    .await;

    match user {
        Ok(Some(user)) => {
            let user_json = to_value(&user).expect("User serialization failed");
            Json(json!({
                "success": true,
                "user": user_json
            })).into_response()
        }
        Ok(None) => JsonResponse::unauthorized("User not found").into_response(),
        Err(e) => {
            eprintln!("DB error in handle_me: {:?}", e);
            JsonResponse::server_error("Database error").into_response()
        }
    }
}
