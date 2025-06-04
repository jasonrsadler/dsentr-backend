use axum::{
    extract::{Json, State},
    response::{IntoResponse, Response},
};
use rand::{distr::Alphanumeric, Rng};
extern crate serde;
use time::{Duration, OffsetDateTime};

use crate::utils::password::hash_password;
use crate::{
    models::{signup::SignupPayload, user::OauthProvider},
    responses::JsonResponse,
    state,
};

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

    if let Err(e) = repo
        .insert_verification_token(user_id, &token, expires_at)
        .await
    {
        eprintln!("Failed to insert verification token: {:?}", e);
        return JsonResponse::server_error("Could not create verification token").into_response();
    }

    if let Err(err) = state
        .mailer
        .send_verification_email(&payload.email, &token)
        .await
    {
        eprintln!("Failed to send verification email: {}", err);
        let _ = repo.cleanup_user_and_token(user_id, &token).await;
        return JsonResponse::server_error("Failed to send verification email").into_response();
    }

    JsonResponse::success("User created. Check your email to verify your account.").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use std::{
        sync::{Arc, Mutex},
        usize,
    };
    use tower::ServiceExt;
    use uuid::Uuid;

    use crate::{
        db::user_repository::{UserId, UserRepository},
        models::{
            signup::SignupPayload,
            user::{OauthProvider, PublicUser, User, UserRole},
        },
        services::{
            oauth::{
                github::mock_github_oauth::MockGitHubOAuth,
                google::mock_google_oauth::MockGoogleOAuth,
            },
            smtp_mailer::{Mailer, MockMailer},
        },
        state::AppState,
    };

    struct MockRepo {
        email_taken: bool,
        fail_create_user: bool,
        fail_insert_token: bool,
        cleaned_up: Arc<Mutex<bool>>,
    }

    #[async_trait]
    impl UserRepository for MockRepo {
        async fn is_email_taken(&self, _email: &str) -> Result<bool, sqlx::Error> {
            Ok(self.email_taken)
        }

        async fn create_user(
            &self,
            _payload: &SignupPayload,
            _hashed_password: &str,
            _provider: OauthProvider,
        ) -> Result<Uuid, sqlx::Error> {
            if self.fail_create_user {
                Err(sqlx::Error::RowNotFound)
            } else {
                Ok(Uuid::new_v4())
            }
        }

        async fn insert_verification_token(
            &self,
            _user_id: Uuid,
            _token: &str,
            _expires_at: OffsetDateTime,
        ) -> Result<(), sqlx::Error> {
            if self.fail_insert_token {
                Err(sqlx::Error::RowNotFound)
            } else {
                Ok(())
            }
        }

        async fn cleanup_user_and_token(
            &self,
            _user_id: Uuid,
            _token: &str,
        ) -> Result<(), sqlx::Error> {
            *self.cleaned_up.lock().unwrap() = true;
            Ok(())
        }

        // === Stubbed methods below ===

        async fn find_user_id_by_email(&self, _email: &str) -> Result<Option<UserId>, sqlx::Error> {
            Ok(Some(UserId { id: Uuid::new_v4() }))
        }

        async fn insert_password_reset_token(
            &self,
            _user_id: Uuid,
            _token: &str,
            _expires_at: OffsetDateTime,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn find_user_by_email(&self, _email: &str) -> Result<Option<User>, sqlx::Error> {
            Ok(Some(User {
                id: Uuid::new_v4(),
                email: "test@example.com".into(),
                password_hash: "hashed".into(),
                first_name: "Test".into(),
                last_name: "User".into(),
                role: Some(UserRole::User),
                created_at: OffsetDateTime::now_utc(),
                plan: None,
                company_name: None,
                oauth_provider: Some(OauthProvider::Email),
            }))
        }

        async fn create_user_with_oauth(
            &self,
            _email: &str,
            _first_name: &str,
            _last_name: &str,
            _provider: OauthProvider,
        ) -> Result<User, sqlx::Error> {
            Ok(User {
                id: Uuid::new_v4(),
                email: "test@example.com".into(),
                password_hash: "hashed".into(),
                first_name: "Test".into(),
                last_name: "User".into(),
                role: Some(UserRole::User),
                created_at: OffsetDateTime::now_utc(),
                plan: None,
                company_name: None,
                oauth_provider: Some(OauthProvider::Email),
            })
        }

        async fn find_public_user_by_id(
            &self,
            _user_id: Uuid,
        ) -> Result<Option<PublicUser>, sqlx::Error> {
            Ok(Some(PublicUser {
                id: Uuid::new_v4(),
                email: "test@example.com".into(),
                first_name: "Test".into(),
                last_name: "User".into(),
                plan: None,
                company_name: None,
                role: Some(UserRole::User),
            }))
        }

        async fn verify_password_reset_token(
            &self,
            _token: &str,
        ) -> Result<Option<Uuid>, sqlx::Error> {
            Ok(Some(Uuid::new_v4()))
        }

        async fn update_user_password(
            &self,
            _user_id: Uuid,
            _hashed_password: &str,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn mark_password_reset_token_used(&self, _token: &str) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn mark_verification_token_used(
            &self,
            _token: &str,
            _: OffsetDateTime,
        ) -> Result<Option<Uuid>, sqlx::Error> {
            Ok(Some(Uuid::new_v4()))
        }

        async fn set_user_verified(&self, _user_id: Uuid) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn insert_early_access_email(&self, _email: &str) -> Result<(), sqlx::Error> {
            Ok(())
        }
    }

    fn test_payload() -> SignupPayload {
        SignupPayload {
            email: "test@example.com".into(),
            password: "password123".into(),
            first_name: "Test".into(),
            last_name: "User".into(),
            provider: None,
            company_name: None,
            country: None,
            tax_id: None,
        }
    }

    async fn run_signup(
        repo: impl UserRepository + 'static,
        mailer: impl Mailer + 'static,
        payload: SignupPayload,
    ) -> axum::response::Response {
        let app = axum::Router::new()
            .route("/", axum::routing::post(handle_signup))
            .with_state(AppState {
                db: Arc::new(repo),
                mailer: Arc::new(mailer),
                github_oauth: Arc::new(MockGitHubOAuth::default()),
                google_oauth: Arc::new(MockGoogleOAuth::default()),
            });

        let request = Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&payload).unwrap()))
            .unwrap();

        app.oneshot(request).await.unwrap()
    }

    #[tokio::test]
    async fn test_email_already_taken() {
        let repo = MockRepo {
            email_taken: true,
            fail_create_user: false,
            fail_insert_token: false,
            cleaned_up: Arc::new(Mutex::new(false)),
        };

        let mailer = MockMailer::default();
        let res = run_signup(repo, mailer, test_payload()).await;
        assert_eq!(res.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_password_hash_fails() {
        let mut payload = test_payload();
        payload.password = "\0".to_string(); // bcrypt will fail

        let repo = MockRepo {
            email_taken: false,
            fail_create_user: false,
            fail_insert_token: false,
            cleaned_up: Arc::new(Mutex::new(false)),
        };

        let mailer = MockMailer::default();
        let res = run_signup(repo, mailer, payload).await;
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_create_user_fails() {
        let repo = MockRepo {
            email_taken: false,
            fail_create_user: true,
            fail_insert_token: false,
            cleaned_up: Arc::new(Mutex::new(false)),
        };

        let mailer = MockMailer::default();
        let res = run_signup(repo, mailer, test_payload()).await;
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_insert_token_fails() {
        let repo = MockRepo {
            email_taken: false,
            fail_create_user: false,
            fail_insert_token: true,
            cleaned_up: Arc::new(Mutex::new(false)),
        };

        let mailer = MockMailer::default();
        let res = run_signup(repo, mailer, test_payload()).await;
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_email_send_fails_and_triggers_cleanup() {
        let cleaned_up = Arc::new(Mutex::new(false));

        let repo = MockRepo {
            email_taken: false,
            fail_create_user: false,
            fail_insert_token: false,
            cleaned_up: Arc::clone(&cleaned_up),
        };

        let mut mailer = MockMailer::default();
        mailer.fail_send = true;

        let res = run_signup(repo, mailer, test_payload()).await;
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(*cleaned_up.lock().unwrap());
    }

    #[tokio::test]
    async fn test_successful_signup() {
        let repo = MockRepo {
            email_taken: false,
            fail_create_user: false,
            fail_insert_token: false,
            cleaned_up: Arc::new(Mutex::new(false)),
        };

        let mailer = MockMailer::default();
        let res = run_signup(repo, mailer, test_payload()).await;

        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["message"],
            "User created. Check your email to verify your account."
        );
    }
}
