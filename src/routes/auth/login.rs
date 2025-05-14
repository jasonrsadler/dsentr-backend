use axum::{
    extract::{Json, State},
    response::{IntoResponse, Response},
    http::{header, HeaderMap, HeaderValue, StatusCode},
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use crate::{responses::JsonResponse, state::AppState, utils::{jwt::{create_jwt, Claims}, password::verify_password}};
use serde::Deserialize;
use chrono::{Utc, Duration};
use time::Duration as TimeDuration;

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

    let user = sqlx::query!(
        "SELECT id, email, password_hash FROM users WHERE email = $1",
        payload.email
    )
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

    match verify_password(&payload.password, &user.password_hash) {
        Ok(true) => {
            let expires_in = if payload.remember {
                Duration::days(30)
            } else {
                Duration::days(7)
            };

            let claims = Claims {
                sub: user.id.to_string(),
                email: user.email,
                exp: (Utc::now() + expires_in).timestamp(),
            };

            match create_jwt(&claims) {
                Ok(token) => {
                    let cookie = Cookie::build(("auth_token", token))
                        .http_only(true)
                        .secure(true)
                        .same_site(SameSite::Lax)
                        .path("/")
                        .max_age(TimeDuration::seconds(expires_in.num_seconds()))
                        .build();

                    let mut headers = HeaderMap::new();
                    headers.insert(
                        header::SET_COOKIE,
                        HeaderValue::from_str(&cookie.to_string()).unwrap(),
                    );

                    (StatusCode::OK, headers, Json(serde_json::json!({ "success": true }))).into_response()
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
