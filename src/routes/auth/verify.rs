use crate::{responses::JsonResponse, state};
use axum::{
    extract::{Json, State},
    response::IntoResponse,
};
use serde::Deserialize;
use time::OffsetDateTime;

#[derive(Deserialize)]
pub struct VerifyEmailPayload {
    token: String,
}

pub async fn verify_email(
    State(state): State<state::AppState>,
    Json(payload): Json<VerifyEmailPayload>,
) -> impl IntoResponse {
    let now = OffsetDateTime::now_utc();

    match state
        .db
        .mark_verification_token_used(&payload.token, now)
        .await
    {
        Ok(Some(user_id)) => {
            if let Err(e) = state.db.set_user_verified(user_id).await {
                eprintln!("Failed to set user as verified: {:?}", e);
                return JsonResponse::server_error("Failed to update user").into_response();
            }
            JsonResponse::success("Email verified successfully").into_response()
        }
        Ok(None) => {
            JsonResponse::bad_request("Invalid, expired, or already used token").into_response()
        }
        Err(_) => JsonResponse::server_error("Something went wrong").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::post,
        Router,
    };
    use serde_json::json;
    use sqlx::Error;
    use std::sync::Arc;
    use tower::ServiceExt;
    use uuid::Uuid;

    use crate::{
        db::mock_db::MockDb,
        services::{
            oauth::{
                github::mock_github_oauth::MockGitHubOAuth,
                google::mock_google_oauth::MockGoogleOAuth,
            },
            smtp_mailer::MockMailer,
        },
        state::AppState,
    };

    use super::verify_email;

    fn test_app(db: MockDb) -> Router {
        Router::new()
            .route("/", post(verify_email))
            .with_state(AppState {
                db: Arc::new(db),
                mailer: Arc::new(MockMailer::default()),
                github_oauth: Arc::new(MockGitHubOAuth::default()),
                google_oauth: Arc::new(MockGoogleOAuth::default()),
            })
    }

    #[tokio::test]
    async fn test_verify_email_success() {
        let user_id = Uuid::new_v4();

        let repo = MockDb {
            mark_verification_token_fn: Box::new(move |_, _| Ok(Some(user_id))),
            set_user_verified_fn: Box::new(|_| Ok(())),
            ..Default::default()
        };

        let app = test_app(repo);
        let req = request_with_token("validtoken");
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_verify_email_invalid_token() {
        let repo = MockDb {
            mark_verification_token_fn: Box::new(|_, _| Ok(None)),
            ..Default::default()
        };

        let app = test_app(repo);
        let req = request_with_token("invalidtoken");
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_verify_email_token_lookup_error() {
        let repo = MockDb {
            mark_verification_token_fn: Box::new(|_, _| Err(Error::RowNotFound)),
            ..Default::default()
        };

        let app = test_app(repo);
        let req = request_with_token("errortoken");
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_verify_email_set_user_error() {
        let user_id = Uuid::new_v4();

        let repo = MockDb {
            mark_verification_token_fn: Box::new(move |_, _| Ok(Some(user_id))),
            set_user_verified_fn: Box::new(|_| Err(sqlx::Error::RowNotFound)),
            ..Default::default()
        };

        let app = test_app(repo);
        let req = request_with_token("validtoken");
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    fn request_with_token(token: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(json!({ "token": token }).to_string()))
            .unwrap()
    }
}
