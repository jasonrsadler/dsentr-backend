use crate::{responses::JsonResponse, state::AppState};
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use axum::{
    extract::{Json, Path, State},
    response::{IntoResponse, Response},
};
use serde::Deserialize;

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
    let password_hash = match Argon2::default().hash_password(new_password.as_bytes(), &salt) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
        routing::{get, post},
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
        state::AppState,
    };

    struct MockRepo {
        behavior: MockBehavior,
    }

    #[derive(Clone, Copy)]
    enum MockBehavior {
        TokenValid,
        TokenInvalid,
        TokenDbError,
        UpdateFails,
        MarkFails,
    }

    #[async_trait]
    impl UserRepository for MockRepo {
        async fn verify_password_reset_token(&self, _: &str) -> Result<Option<Uuid>, Error> {
            match self.behavior {
                MockBehavior::TokenValid => Ok(Some(Uuid::new_v4())),
                MockBehavior::TokenInvalid => Ok(None),
                MockBehavior::TokenDbError => Err(Error::RowNotFound),
                _ => Ok(Some(Uuid::new_v4())),
            }
        }

        async fn update_user_password(&self, _: Uuid, _: &str) -> Result<(), Error> {
            match self.behavior {
                MockBehavior::UpdateFails => Err(Error::RowNotFound),
                _ => Ok(()),
            }
        }

        async fn mark_password_reset_token_used(&self, _: &str) -> Result<(), Error> {
            match self.behavior {
                MockBehavior::MarkFails => Err(Error::RowNotFound),
                _ => Ok(()),
            }
        }

        // Other trait methods are no-ops for this test
        async fn find_user_id_by_email(&self, _: &str) -> Result<Option<UserId>, Error> {
            Ok(None)
        }

        async fn insert_password_reset_token(
            &self,
            _: Uuid,
            _: &str,
            _: OffsetDateTime,
        ) -> Result<(), Error> {
            Ok(())
        }

        async fn find_user_by_email(&self, _: &str) -> Result<Option<User>, Error> {
            Ok(None)
        }

        async fn create_user_with_oauth(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: OauthProvider,
        ) -> Result<User, Error> {
            Ok(User {
                id: Uuid::new_v4(),
                email: "".into(),
                first_name: "".into(),
                last_name: "".into(),
                role: Some(UserRole::User),
                password_hash: "".into(),
                plan: None,
                company_name: None,
                oauth_provider: Some(OauthProvider::Google),
                created_at: OffsetDateTime::now_utc(),
            })
        }

        async fn find_public_user_by_id(&self, _: Uuid) -> Result<Option<PublicUser>, Error> {
            Ok(None)
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
        let db = Arc::new(MockRepo { behavior });
        let state = AppState {
            db,
            mailer: Arc::new(crate::services::smtp_mailer::MockMailer::default()),
        };

        Router::new()
            .route("/reset-password", post(handle_reset_password))
            .route("/reset-password/{token}", get(handle_verify_token))
            .with_state(state)
    }

    #[tokio::test]
    async fn test_verify_token_valid() {
        let app = make_app(MockBehavior::TokenValid);
        let token = Uuid::new_v4().to_string();

        let response = app
            .oneshot(
                Request::builder()
                    .uri(&format!("/reset-password/{token}"))
                    .method("GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "Token is valid.");
    }

    #[tokio::test]
    async fn test_verify_token_invalid() {
        let app = make_app(MockBehavior::TokenInvalid);
        let token = "invalid-token";

        let response = app
            .oneshot(
                Request::builder()
                    .uri(&format!("/reset-password/{token}"))
                    .method("GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "Invalid or expired token.");
    }

    #[tokio::test]
    async fn test_reset_password_success() {
        let app = make_app(MockBehavior::TokenValid);
        let body = json!({
            "token": Uuid::new_v4().to_string(),
            "password": "newpassword123"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/reset-password")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["message"], "Password has been reset.");
    }

    #[tokio::test]
    async fn test_reset_password_update_fails() {
        let app = make_app(MockBehavior::UpdateFails);
        let body = json!({
            "token": Uuid::new_v4().to_string(),
            "password": "newpassword123"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/reset-password")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_reset_password_mark_fails() {
        let app = make_app(MockBehavior::MarkFails);
        let body = json!({
            "token": Uuid::new_v4().to_string(),
            "password": "newpassword123"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/reset-password")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_reset_password_token_invalid() {
        let app = make_app(MockBehavior::TokenInvalid);
        let body = json!({
            "token": "badtoken",
            "password": "newpassword123"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/reset-password")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_reset_password_token_db_error() {
        let app = make_app(MockBehavior::TokenDbError);
        let body = json!({
            "token": "someerror",
            "password": "newpassword123"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/reset-password")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
