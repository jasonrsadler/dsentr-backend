use crate::responses::JsonResponse;
use crate::{models::early_access::EarlyAccessPayload, state::AppState};
use axum::{
    extract::{Json, State},
    response::{IntoResponse, Response},
};

pub async fn handle_early_access(
    State(state): State<AppState>,
    Json(payload): Json<EarlyAccessPayload>,
) -> Response {
    let repo = &state.db;

    match repo.insert_early_access_email(&payload.email).await {
        Ok(_) => JsonResponse::success("Thanks for signing up!").into_response(),
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
            eprintln!("unique violation insert error: {:?}", db_err.to_string());
            JsonResponse::conflict("You're already on the list!").into_response()
        }
        Err(e) => {
            eprintln!("insert error: {:?}", e.to_string());
            JsonResponse::server_error("Something went wrong").into_response()
        }
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
    use sqlx::error::{BoxDynError, DatabaseError};
    use std::sync::Arc;
    use std::{borrow::Cow, error::Error};
    use tower::ServiceExt;

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

    use super::handle_early_access;

    fn test_app(db: MockDb) -> Router {
        Router::new()
            .route("/", post(handle_early_access))
            .with_state(AppState {
                db: Arc::new(db),
                mailer: Arc::new(MockMailer::default()),
                github_oauth: Arc::new(MockGitHubOAuth::default()),
                google_oauth: Arc::new(MockGoogleOAuth::default()),
            })
    }

    fn request_with_email(email: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(format!(r#"{{"email":"{}"}}"#, email)))
            .unwrap()
    }

    #[tokio::test]
    async fn test_early_access_success() {
        let repo = MockDb {
            insert_early_access_email_fn: Box::new(|_| Ok(())),
            ..Default::default()
        };

        let app = test_app(repo);
        let res = app
            .oneshot(request_with_email("user@example.com"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_early_access_duplicate() {
        struct FakeDbErr;
        impl std::fmt::Debug for FakeDbErr {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "fake")
            }
        }
        impl std::fmt::Display for FakeDbErr {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "fake")
            }
        }
        impl Error for FakeDbErr {}
        impl DatabaseError for FakeDbErr {
            fn message(&self) -> &str {
                "duplicate key value violates unique constraint"
            }

            fn code(&self) -> Option<Cow<'_, str>> {
                Some(Cow::Borrowed("23505")) // Postgres unique_violation
            }

            fn constraint(&self) -> Option<&str> {
                Some("early_access_email_key")
            }

            fn as_error(&self) -> &(dyn Error + Send + Sync + 'static) {
                self
            }

            fn as_error_mut(&mut self) -> &mut (dyn Error + Send + Sync + 'static) {
                self
            }

            fn into_error(self: Box<Self>) -> BoxDynError {
                self
            }

            fn kind(&self) -> sqlx::error::ErrorKind {
                sqlx::error::ErrorKind::UniqueViolation
            }
        }

        let repo = MockDb {
            insert_early_access_email_fn: Box::new(|_| {
                Err(sqlx::Error::Database(Box::new(FakeDbErr)))
            }),
            ..Default::default()
        };

        let app = test_app(repo);
        let res = app
            .oneshot(request_with_email("duplicate@example.com"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_early_access_generic_error() {
        let repo = MockDb {
            insert_early_access_email_fn: Box::new(|_| Err(sqlx::Error::RowNotFound)),
            ..Default::default()
        };

        let app = test_app(repo);
        let res = app
            .oneshot(request_with_email("fail@example.com"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
