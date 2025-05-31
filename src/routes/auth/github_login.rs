use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::Engine;
use rand_core::{OsRng, RngCore};

use crate::{
    models::user::OauthProvider,
    responses::JsonResponse,
    services::oauth::github::{errors::GitHubAuthError, models::GitHubCallback},
    state::AppState,
    utils::jwt::create_jwt,
};

/// Redirects to GitHub's OAuth authorization page with CSRF protection
pub async fn github_login(jar: CookieJar) -> impl IntoResponse {
    let mut csrf_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut csrf_bytes);
    let csrf_token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(csrf_bytes);

    let state_cookie = Cookie::build(("oauth_state", csrf_token.clone()))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(time::Duration::minutes(10))
        .build();

    let client_id = std::env::var("GITHUB_CLIENT_ID").unwrap();
    let redirect_uri = std::env::var("GITHUB_REDIRECT_URI").unwrap();
    let scope = "read:user user:email";

    let github_url = format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope={}&state={}",
        client_id, redirect_uri, scope, csrf_token,
    );

    (jar.add(state_cookie), Redirect::to(&github_url))
}

/// Handles the GitHub OAuth callback, validates state, and logs in/creates user
pub async fn github_callback(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(params): Query<GitHubCallback>,
) -> Response {
    let code = &params.code;
    let state_param = &params.state;

    let expected_state = match jar.get("oauth_state").map(|c| c.value().to_string()) {
        Some(state) => state,
        None => {
            return JsonResponse::redirect_to_login_with_error(
                &GitHubAuthError::MissingStateCookie.to_string(),
            )
            .into_response();
        }
    };

    if state_param != &expected_state {
        return JsonResponse::redirect_to_login_with_error(
            &GitHubAuthError::InvalidState.to_string(),
        )
        .into_response();
    }

    let token = match state.github_oauth.exchange_code_for_token(code).await {
        Ok(token) => token,
        Err(e) => {
            eprintln!("GitHub token exchange error: {:?}", e);
            return JsonResponse::redirect_to_login_with_error(
                &GitHubAuthError::TokenExchangeFailed.to_string(),
            )
            .into_response();
        }
    };

    let user_info = match state.github_oauth.fetch_user_info(&token).await {
        Ok(info) => info,
        Err(e) => {
            eprintln!("GitHub user info error: {:?}", e);
            return JsonResponse::redirect_to_login_with_error(
                &GitHubAuthError::InvalidUserInfo.to_string(),
            )
            .into_response();
        }
    };

    let email = user_info.email;

    let first_name = user_info.first_name;
    let last_name = user_info.last_name; // GitHub doesn’t expose last name

    let user = match state.db.find_user_by_email(&email).await {
        Ok(Some(user)) => match (&user.oauth_provider, OauthProvider::Github) {
            (Some(OauthProvider::Github), _) => user,

            (None, _) => {
                return JsonResponse::redirect_to_login_with_error(
                    "This account was created using email/password. Please log in with email.",
                )
                .into_response();
            }

            (Some(other), _) => {
                return JsonResponse::redirect_to_login_with_error(&format!(
                    "This account is linked to {:?}. Please use that provider to log in.",
                    other
                ))
                .into_response();
            }
        },

        Ok(None) => {
            match state
                .db
                .create_user_with_oauth(&email, &first_name, &last_name, OauthProvider::Github)
                .await
            {
                Ok(new_user) => new_user,
                Err(e) => {
                    eprintln!("DB user creation error: {:?}", e);
                    return JsonResponse::redirect_to_login_with_error(
                        &GitHubAuthError::UserCreationFailed.to_string(),
                    )
                    .into_response();
                }
            }
        }

        Err(e) => {
            eprintln!("DB lookup error: {:?}", e);
            return JsonResponse::redirect_to_login_with_error(
                &GitHubAuthError::DbError(e).to_string(),
            )
            .into_response();
        }
    };

    let claims = crate::routes::auth::claims::Claims {
        id: user.id.to_string(),
        role: user.role,
        exp: (chrono::Utc::now() + chrono::Duration::days(30)).timestamp() as usize,
        email: email.to_string(),
        first_name,
        last_name,
        plan: None,
        company_name: None,
    };

    let jwt = match create_jwt(&claims) {
        Ok(token) => token,
        Err(_) => {
            return JsonResponse::redirect_to_login_with_error(
                &GitHubAuthError::JwtCreationFailed.to_string(),
            )
            .into_response();
        }
    };

    let auth_cookie = Cookie::build(("auth_token", jwt))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(time::Duration::days(30))
        .build();

    let clear_state_cookie = Cookie::build(("oauth_state", ""))
        .path("/")
        .max_age(time::Duration::seconds(0))
        .build();

    let jar = CookieJar::new().add(auth_cookie).add(clear_state_cookie);

    let frontend_url =
        std::env::var("FRONTEND_ORIGIN").unwrap_or_else(|_| "https://localhost:5173".to_string());

    (jar, Redirect::to(&format!("{}/dashboard", frontend_url))).into_response()
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        response::IntoResponse,
        routing::get,
        Router,
    };
    use axum_extra::extract::cookie::CookieJar;
    use std::sync::Arc;
    use tower::ServiceExt;

    use crate::{
        db::mock_db::MockDb,
        routes::auth::github_login::{github_callback, github_login},
        services::{
            oauth::{
                github::{
                    errors::GitHubAuthError,
                    mock_github_oauth::MockGitHubOAuth,
                    models::{GitHubCallback, GitHubToken},
                    service::{GitHubOAuthService, GitHubUserInfo},
                },
                google::mock_google_oauth::MockGoogleOAuth,
            },
            smtp_mailer::MockMailer,
        },
        state::AppState,
    }; // for `.oneshot()`

    #[tokio::test]
    async fn test_github_login_sets_cookie_and_redirects() {
        std::env::set_var("GITHUB_CLIENT_ID", "test_client_id");
        std::env::set_var("GITHUB_REDIRECT_URI", "test_client_secret");
        let app = Router::new().route("/auth/github", get(github_login));

        let response = app
            .oneshot(Request::get("/auth/github").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert!(matches!(
            response.status(),
            StatusCode::FOUND | StatusCode::SEE_OTHER
        ));

        let headers = response.headers();
        let location = headers.get("location").unwrap().to_str().unwrap();
        assert!(location.contains("github.com/login/oauth/authorize"));

        let set_cookie = headers.get("set-cookie").unwrap().to_str().unwrap();
        assert!(set_cookie.contains("oauth_state="));
    }

    #[tokio::test]
    async fn test_github_callback_missing_state_cookie() {
        let repo = Arc::new(MockDb::default());
        let mailer = Arc::new(MockMailer::default());
        let google_oauth = Arc::new(MockGoogleOAuth::default());
        let github_oauth = Arc::new(MockGitHubOAuth::default());
        let state = AppState {
            db: repo,
            mailer,
            google_oauth,
            github_oauth,
        };

        let params = GitHubCallback {
            code: "dummy".into(),
            state: "invalid".into(),
        };

        let jar = CookieJar::new(); // no cookies = missing oauth_state

        let response = github_callback(
            axum::extract::State(state),
            jar,
            axum::extract::Query(params),
        )
        .await
        .into_response();

        // Should redirect to /login with an error
        assert!(
            matches!(response.status(), StatusCode::FOUND | StatusCode::SEE_OTHER),
            "Expected 302 or 303, got {}",
            response.status()
        );

        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();

        assert!(location.contains("/login?error="));
        let binding = GitHubAuthError::MissingStateCookie.to_string();
        let expected = urlencoding::encode(&binding);
        assert!(location.contains(&expected.to_string()));
    }

    #[tokio::test]
    async fn test_github_callback_internal_failure() {
        std::env::set_var("GITHUB_CLIENT_ID", "test_client_id");
        std::env::set_var("GITHUB_CLIENT_SECRET", "test_client_secret");

        // Mock that simulates failure — override GitHubOAuth behavior
        #[derive(Default)]
        struct FailingGitHubOAuth;

        #[async_trait]
        impl GitHubOAuthService for FailingGitHubOAuth {
            async fn exchange_code_for_token(
                &self,
                _code: &str,
            ) -> Result<GitHubToken, GitHubAuthError> {
                Err(GitHubAuthError::TokenExchangeFailed)
            }

            async fn fetch_user_info(
                &self,
                _token: &GitHubToken,
            ) -> Result<GitHubUserInfo, GitHubAuthError> {
                unreachable!()
            }
        }

        let app_state = AppState {
            db: Arc::new(MockDb::default()),
            mailer: Arc::new(MockMailer::default()),
            google_oauth: Arc::new(MockGoogleOAuth::default()),
            github_oauth: Arc::new(FailingGitHubOAuth),
        };

        let params = GitHubCallback {
            code: "dummy".into(),
            state: "dummy".into(),
        };

        let jar = CookieJar::new().add(axum_extra::extract::cookie::Cookie::new(
            "oauth_state",
            "dummy",
        ));

        let response = github_callback(
            axum::extract::State(app_state),
            jar,
            axum::extract::Query(params),
        )
        .await
        .into_response();

        // Expect redirect to /login?error=GitHub+login+failed
        assert!(
            matches!(response.status(), StatusCode::FOUND | StatusCode::SEE_OTHER),
            "Expected 302 or 303, got {}",
            response.status()
        );

        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.contains("/login?error="));
        eprintln!("Location: {}", location);
        eprintln!("Expected error: {:?}", GitHubAuthError::TokenExchangeFailed);
        let binding = GitHubAuthError::TokenExchangeFailed.to_string();
        let expected = urlencoding::encode(&binding);
        assert!(location.contains(&expected.to_string()));
    }
}
