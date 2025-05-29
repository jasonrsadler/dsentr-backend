use axum::{
    extract::{Json, State},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{responses::JsonResponse, state::AppState};

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

    match db.find_user_id_by_email(email).await {
        Ok(Some(user_id)) => {
            let token = Uuid::new_v4().to_string();
            let expiry = OffsetDateTime::now_utc() + Duration::minutes(30);

            if let Err(e) = db
                .insert_password_reset_token(user_id.id, &token, expiry)
                .await
            {
                eprintln!("Failed to insert password reset token: {:?}", e);
            } else if let Err(e) = mailer.send_reset_email(email, &token).await {
                eprintln!("Failed to send reset email: {:?}", e);
            }
        }
        Ok(None) => {}
        Err(e) => {
            eprintln!("Error looking up user by email: {:?}", e);
        }
    }

    JsonResponse::success("If that email exists, a reset link has been sent.").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
        routing::post,
        Router,
    };
    use serde_json::json;
    use sqlx::Error;
    use std::sync::Arc;
    use time::OffsetDateTime;
    use tower::util::ServiceExt;
    use uuid::Uuid;

    use crate::{
        db::user_repository::{UserId, UserRepository},
        models::{
            signup::SignupPayload,
            user::{OauthProvider, PublicUser, User, UserRole},
        },
        services::smtp_mailer::MockMailer,
        state::AppState,
    };

    struct MockRepo {
        behavior: MockBehavior,
    }

    enum MockBehavior {
        UserFound,
        UserNotFound,
        DbError,
        InsertError,
    }

    #[async_trait]
    impl UserRepository for MockRepo {
        async fn find_user_id_by_email(&self, _email: &str) -> Result<Option<UserId>, Error> {
            match self.behavior {
                MockBehavior::DbError => Err(Error::RowNotFound),
                MockBehavior::UserNotFound => Ok(None),
                _ => Ok(Some(UserId { id: Uuid::new_v4() })),
            }
        }

        async fn insert_password_reset_token(
            &self,
            _user_id: Uuid,
            _token: &str,
            _expiry: OffsetDateTime,
        ) -> Result<(), Error> {
            match self.behavior {
                MockBehavior::InsertError => Err(Error::RowNotFound),
                _ => Ok(()),
            }
        }

        async fn find_user_by_email(&self, _: &str) -> Result<Option<User>, Error> {
            Ok(None)
        }

        async fn create_user_with_oauth(
            &self,
            email: &str,
            first_name: &str,
            last_name: &str,
            provider: OauthProvider,
        ) -> Result<User, Error> {
            Ok(User {
                id: Uuid::new_v4(),
                email: email.to_string(),
                first_name: first_name.to_string(),
                last_name: last_name.to_string(),
                role: Some(UserRole::User),
                password_hash: "".to_string(),
                plan: None,
                company_name: None,
                oauth_provider: Some(provider),
                created_at: OffsetDateTime::now_utc(),
            })
        }

        async fn find_public_user_by_id(&self, _: Uuid) -> Result<Option<PublicUser>, Error> {
            Ok(None)
        }

        async fn verify_password_reset_token(&self, _: &str) -> Result<Option<Uuid>, Error> {
            Ok(None)
        }

        async fn update_user_password(&self, _: Uuid, _: &str) -> Result<(), Error> {
            Ok(())
        }

        async fn mark_password_reset_token_used(&self, _: &str) -> Result<(), Error> {
            Ok(())
        }

        async fn is_email_taken(&self, _: &str) -> Result<bool, Error> {
            Ok(false)
        }

        async fn create_user(
            &self,
            _: &SignupPayload,
            _: &str,
            _: OauthProvider,
        ) -> Result<Uuid, Error> {
            Ok(Uuid::new_v4())
        }

        async fn insert_verification_token(
            &self,
            _: Uuid,
            _: &str,
            _: OffsetDateTime,
        ) -> Result<(), Error> {
            Ok(())
        }

        async fn cleanup_user_and_token(&self, _: Uuid, _: &str) -> Result<(), Error> {
            Ok(())
        }

        async fn mark_verification_token_used(
            &self,
            _: &str,
            _: OffsetDateTime,
        ) -> Result<Option<Uuid>, Error> {
            Ok(Some(Uuid::new_v4()))
        }

        async fn set_user_verified(&self, _: Uuid) -> Result<(), Error> {
            Ok(())
        }

        async fn insert_early_access_email(&self, _: &str) -> Result<(), Error> {
            Ok(())
        }
    }

    fn make_app(behavior: MockBehavior) -> Router {
        let repo = Arc::new(MockRepo { behavior });
        let mailer = Arc::new(MockMailer::default());
        let state = AppState { db: repo, mailer };

        Router::new()
            .route("/forgot-password", post(handle_forgot_password))
            .with_state(state)
    }

    #[tokio::test]
    async fn test_user_found_and_email_sent() {
        let app = make_app(MockBehavior::UserFound);

        let body = json!({ "email": "test@example.com" });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/forgot-password")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            json["message"],
            "If that email exists, a reset link has been sent."
        );
    }

    #[tokio::test]
    async fn test_user_not_found() {
        let app = make_app(MockBehavior::UserNotFound);

        let body = json!({ "email": "doesnotexist@example.com" });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/forgot-password")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_lookup_fails() {
        let app = make_app(MockBehavior::DbError);

        let body = json!({ "email": "oops@example.com" });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/forgot-password")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_token_insert_fails() {
        let app = make_app(MockBehavior::InsertError);

        let body = json!({ "email": "insertfail@example.com" });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/forgot-password")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_email_send_fails() {
        let repo = Arc::new(MockRepo {
            behavior: MockBehavior::UserFound,
        });
        let mailer = Arc::new(MockMailer::default());
        let state = AppState { db: repo, mailer };

        let app = Router::new()
            .route("/forgot-password", post(handle_forgot_password))
            .with_state(state);

        let body = json!({ "email": "failtosend@example.com" });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/forgot-password")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
