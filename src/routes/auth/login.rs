use crate::routes::auth::claims::Claims;
use crate::{
    responses::JsonResponse,
    state::AppState,
    utils::{jwt::create_jwt, password::verify_password},
};

use axum::{
    extract::{Json, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, to_value};
use time::Duration as TimeDuration;
use uuid::Uuid;

use super::session::AuthSession;

#[derive(Deserialize, Serialize)]
pub struct LoginPayload {
    pub email: String,
    pub password: String,
    pub remember: bool,
}

pub async fn handle_login(
    State(app_state): State<AppState>,
    Json(payload): Json<LoginPayload>,
) -> Response {
    eprintln!("Password provided: {}", payload.password);
    eprintln!("User found: {:?}", payload.email);
    let user = app_state.db.find_user_by_email(&payload.email).await;
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
        ))
        .into_response();
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
                company_name: user.company_name.clone(),
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
                    )
                        .into_response()
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
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    let user = app_state.db.find_public_user_by_id(user_id).await;

    match user {
        Ok(Some(user)) => {
            let user_json = to_value(&user).expect("User serialization failed");
            Json(json!({
                "success": true,
                "user": user_json
            }))
            .into_response()
        }
        Ok(None) => JsonResponse::unauthorized("User not found").into_response(),
        Err(e) => {
            eprintln!("DB error in handle_me: {:?}", e);
            JsonResponse::server_error("Database error").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use argon2::{Argon2, PasswordHasher};
    use axum::{
        body::{to_bytes, Body},
        extract::Request,
        http::StatusCode,
        routing::post,
        Router,
    };
    use password_hash::SaltString;
    use rand_core::OsRng;
    use time::OffsetDateTime;
    use tower::ServiceExt;
    use uuid::Uuid;

    use crate::{
        db::{mock_db::MockDb, user_repository::UserRepository},
        models::user::{OauthProvider, User, UserRole},
        routes::auth::login::LoginPayload,
        services::{
            oauth::{
                github::mock_github_oauth::MockGitHubOAuth,
                google::mock_google_oauth::MockGoogleOAuth,
            },
            smtp_mailer::MockMailer,
        },
        state::AppState,
    };

    use super::handle_login;

    fn test_user_with_password(password: &str) -> (User, String) {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        let user = User {
            id: Uuid::new_v4(),
            email: "test@example.com".into(),
            password_hash: hash.clone(),
            oauth_provider: None,
            first_name: "Test".into(),
            last_name: "User".into(),
            role: Some(UserRole::User),
            plan: Some("free".into()),
            company_name: Some("Acme Corp".into()),
            created_at: OffsetDateTime::now_utc(),
        };

        (user, password.to_string())
    }

    fn build_app(db: impl UserRepository + 'static) -> Router {
        let app_state = AppState {
            db: Arc::new(db),
            mailer: Arc::new(MockMailer::default()), // Not used in these tests
            google_oauth: Arc::new(MockGoogleOAuth::default()), // Not used in these tests
            github_oauth: Arc::new(MockGitHubOAuth::default()), // Not used in these tests
        };

        Router::new()
            .route("/login", post(handle_login))
            .with_state(app_state)
    }

    // --- Tests ---

    #[tokio::test]
    async fn test_login_success() {
        let password = "password123";
        let (user, _) = test_user_with_password(password);
        eprintln!("User going into MockDb: {:?}", user.email);
        std::env::set_var("JWT_SECRET", "test_secret_key");
        let app = build_app(MockDb {
            find_user_result: Some(user.clone()),
            ..Default::default()
        });

        let payload = LoginPayload {
            email: user.email.clone(),
            password: password.to_string(),
            remember: true,
        };

        let res = app
            .oneshot(
                Request::post("/login")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["user"]["email"], user.email);
    }

    #[tokio::test]
    async fn test_login_wrong_password() {
        let password = "password123";
        let (user, _) = test_user_with_password(password);

        let app = build_app(MockDb {
            find_user_result: Some(user.clone()),
            ..Default::default()
        });

        let payload = LoginPayload {
            email: user.email.clone(),
            password: "wrong-password".to_string(),
            remember: false,
        };

        let res = app
            .oneshot(
                Request::post("/login")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_login_user_not_found() {
        let app = build_app(MockDb {
            find_user_result: None,
            ..Default::default()
        });

        let payload = LoginPayload {
            email: "unknown@example.com".to_string(),
            password: "irrelevant".to_string(),
            remember: false,
        };

        let res = app
            .oneshot(
                Request::post("/login")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_login_oauth_only_user() {
        let password_hash = "".to_string();
        let (mut user, _) = test_user_with_password(&password_hash);
        user.oauth_provider = Some(OauthProvider::Google);

        let app = build_app(MockDb {
            find_user_result: Some(user.clone()),
            ..Default::default()
        });

        let payload = LoginPayload {
            email: user.email.clone(),
            password: "irrelevant".to_string(),
            remember: false,
        };

        let res = app
            .oneshot(
                Request::post("/login")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_login_db_error() {
        let app = build_app(MockDb {
            should_fail: true,
            ..Default::default()
        });

        let payload = LoginPayload {
            email: "test@example.com".to_string(),
            password: "doesntmatter".to_string(),
            remember: false,
        };

        let res = app
            .oneshot(
                Request::post("/login")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
